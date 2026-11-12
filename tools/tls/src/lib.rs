//! Proof-of-concept TLS sidecar for web-platform-tests.
//!
//! Terminates TLS (selecting a per-SNI profile) and forwards the request to a
//! backend (wptserve) over loopback, terminating HTTP/2 and translating it to
//! HTTP/1.1. The negotiated parameters are echoed back as `X-Negotiated-*`
//! response headers so tests can assert on them.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::future::Future;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{Acceptor, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned, SupportedProtocolVersion};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 8 * 1024;
const BACKEND_TIMEOUT: Duration = Duration::from_secs(30);
const COPY_CHUNK: usize = 16 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listeners: Vec<ListenerSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerSpec {
    /// Address to listen on, e.g. `127.0.0.1:8447`.
    pub listen: String,
    /// Plaintext HTTP backend, e.g. `127.0.0.1:8000`.
    pub backend: String,
    /// Crypto provider: `aws-lc-rs` (default) or `ring`.
    #[serde(default)]
    pub provider: Option<String>,
    /// Profile used when the SNI name matches none (or is absent).
    #[serde(default)]
    pub default_profile: Option<String>,
    /// Profiles keyed by SNI server name (or its leftmost label).
    pub profiles: HashMap<String, ProfileSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSpec {
    /// PEM certificate chain presented to clients.
    pub cert: String,
    /// PEM private key.
    pub key: String,
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub max_version: Option<String>,
    /// ALPN protocols in server-preference order, e.g. `["h2", "http/1.1"]`.
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub client_auth: ClientAuth,
    /// CA bundle used to verify client certificates.
    #[serde(default)]
    pub client_ca: Option<String>,
    /// If set, only these cipher suites (rustls/IANA names) are offered.
    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,
    /// If set, only these key exchange groups are offered.
    #[serde(default)]
    pub key_exchange: Option<Vec<String>>,
    /// Bytes of 0-RTT early data accepted; 0 (the default) disables 0-RTT.
    #[serde(default)]
    pub max_early_data: u32,
    /// TLS 1.3 session tickets sent; the rustls default keeps resumption on.
    #[serde(default)]
    pub tls13_tickets: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuth {
    #[default]
    None,
    Request,
    Require,
}

struct ListenerRuntime {
    backend: String,
    default_profile: Option<String>,
    profiles: HashMap<String, Arc<ServerConfig>>,
}

impl ListenerRuntime {
    fn config_for(&self, sni: Option<&str>) -> Result<Arc<ServerConfig>> {
        if let Some(name) = sni {
            let name = name.trim_end_matches('.');
            if let Some(config) = self.profiles.get(name) {
                return Ok(config.clone());
            }
            if let Some(label) = name.split('.').next() {
                if let Some(config) = self.profiles.get(label) {
                    return Ok(config.clone());
                }
            }
        }
        if let Some(default) = &self.default_profile {
            if let Some(config) = self.profiles.get(default) {
                return Ok(config.clone());
            }
        }
        if self.profiles.len() == 1 {
            return Ok(self.profiles.values().next().unwrap().clone());
        }
        Err(format!("no TLS profile for SNI {sni:?}").into())
    }
}

pub struct RunningServer {
    pub addrs: Vec<(String, SocketAddr)>,
    shutdown: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

impl RunningServer {
    pub fn wait(mut self) {
        for handle in std::mem::take(&mut self.handles) {
            let _ = handle.join();
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

pub fn start(config: Config) -> Result<RunningServer> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut addrs = Vec::new();
    let mut handles = Vec::new();

    for spec in config.listeners {
        ensure_loopback(&spec.listen, "listen address")?;
        ensure_loopback(&spec.backend, "backend address")?;
        let runtime = Arc::new(build_listener(&spec)?);
        let listener = TcpListener::bind(&spec.listen)?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let name = spec
            .default_profile
            .clone()
            .unwrap_or_else(|| "listener".to_string());
        addrs.push((name, addr));

        let shutdown = shutdown.clone();
        handles.push(thread::spawn(move || {
            accept_loop(listener, runtime, shutdown);
        }));
    }

    Ok(RunningServer {
        addrs,
        shutdown,
        handles,
    })
}

pub fn load_config(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

/// The sidecar only ever talks to loopback: it is the TLS front end for a
/// local test server, and the backend hop is plaintext.
fn ensure_loopback(address: &str, what: &str) -> Result<()> {
    use std::net::ToSocketAddrs;

    let addrs: Vec<SocketAddr> = address
        .to_socket_addrs()
        .map_err(|err| format!("invalid {what} {address:?}: {err}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{what} {address:?} did not resolve").into());
    }
    if let Some(addr) = addrs.iter().find(|addr| !addr.ip().is_loopback()) {
        return Err(format!(
            "{what} {address:?} resolves to {}, which is not loopback",
            addr.ip()
        )
        .into());
    }
    Ok(())
}

fn accept_loop(listener: TcpListener, runtime: Arc<ListenerRuntime>, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let runtime = runtime.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream, runtime) {
                        eprintln!("wpt-tls-server: connection error: {err}");
                    }
                });
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) => {
                eprintln!("wpt-tls-server: accept error: {err}");
                return;
            }
        }
    }
}

fn handle_client(tcp: TcpStream, runtime: Arc<ListenerRuntime>) -> io::Result<()> {
    let mut acceptor = Acceptor::default();
    let mut tcp = tcp;
    loop {
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let sni = accepted.client_hello().server_name().map(str::to_string);
                let config = runtime
                    .config_for(sni.as_deref())
                    .map_err(io::Error::other)?;
                let conn = match accepted.into_connection(config) {
                    Ok(conn) => conn,
                    Err((err, mut alert)) => {
                        let _ = alert.write_all(&mut tcp);
                        return Err(io::Error::other(err));
                    }
                };
                let tls = StreamOwned::new(conn, tcp);
                return serve(tls, &runtime.backend);
            }
            Ok(None) => {
                if acceptor.read_tls(&mut tcp)? == 0 {
                    return Ok(());
                }
            }
            Err((err, mut alert)) => {
                let _ = alert.write_all(&mut tcp);
                return Err(io::Error::other(err));
            }
        }
    }
}

fn serve(mut tls: StreamOwned<ServerConnection, TcpStream>, backend: &str) -> io::Result<()> {
    tls.sock.set_read_timeout(Some(BACKEND_TIMEOUT))?;
    tls.sock.set_write_timeout(Some(BACKEND_TIMEOUT))?;
    if tls.conn.alpn_protocol() == Some(b"h2") {
        return serve_h2(tls, backend);
    }
    proxy_h1(&mut tls, backend)
}

fn negotiated_params(tls: &StreamOwned<ServerConnection, TcpStream>) -> (String, String, String) {
    let version = format!(
        "{:?}",
        tls.conn
            .protocol_version()
            .unwrap_or(rustls::ProtocolVersion::TLSv1_2)
    );
    let cipher = tls
        .conn
        .negotiated_cipher_suite()
        .map(|s| suite_name(&s))
        .unwrap_or_default();
    let alpn = tls
        .conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_default();
    (version, cipher, alpn)
}

fn proxy_h1(tls: &mut StreamOwned<ServerConnection, TcpStream>, backend: &str) -> io::Result<()> {
    loop {
        let head = read_head(tls)?;
        if head.is_empty() {
            return Ok(());
        }
        let request = rewrite_request_head(&head);

        let mut backend_stream = match TcpStream::connect(backend) {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("wpt-tls-server: backend connect failed: {err}");
                return send_bad_gateway(tls);
            }
        };
        backend_stream.set_read_timeout(Some(BACKEND_TIMEOUT))?;
        backend_stream.set_write_timeout(Some(BACKEND_TIMEOUT))?;
        backend_stream.write_all(&request.bytes)?;

        if request.expect_continue {
            tls.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            tls.flush()?;
        }
        match request.body {
            Body::None => {}
            Body::Length(length) => {
                io::copy(&mut (&mut *tls).take(length), &mut backend_stream)?;
            }
            Body::Chunked => copy_chunked(&mut *tls, &mut backend_stream)?,
        }

        let response_head = read_head(&mut backend_stream)?;
        if response_head.is_empty() {
            return send_bad_gateway(tls);
        }
        let framing = response_framing(&response_head, request.is_head);
        let keep_alive = request.keep_alive && framing != Framing::Eof;
        let response_head = rewrite_response_head(tls, &response_head, keep_alive);
        tls.write_all(&response_head)?;
        relay_body(&framing, &mut backend_stream, tls)?;
        tls.flush()?;

        if !keep_alive {
            tls.conn.send_close_notify();
            tls.flush()?;
            return Ok(());
        }
    }
}

fn relay_body<R: Read, W: Write>(
    framing: &Framing,
    backend: &mut R,
    client: &mut W,
) -> io::Result<()> {
    match framing {
        Framing::None => Ok(()),
        Framing::Length(length) => {
            io::copy(&mut backend.take(*length), client)?;
            Ok(())
        }
        Framing::Chunked => copy_chunked(backend, client),
        Framing::Eof => {
            io::copy(backend, client)?;
            Ok(())
        }
    }
}

fn copy_chunked<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> io::Result<()> {
    loop {
        let line = read_line(reader)?;
        writer.write_all(&line)?;
        let field = String::from_utf8_lossy(&line);
        let field = field.trim().split(';').next().unwrap_or("");
        let size = usize::from_str_radix(field, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        if size == 0 {
            loop {
                let trailer = read_line(reader)?;
                writer.write_all(&trailer)?;
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
        }
        let mut chunk = vec![0u8; size + 2];
        reader.read_exact(&mut chunk)?;
        writer.write_all(&chunk)?;
    }
}

fn send_bad_gateway(tls: &mut StreamOwned<ServerConnection, TcpStream>) -> io::Result<()> {
    tls.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
    tls.conn.send_close_notify();
    tls.flush()
}

/// Read bytes up to and including the first `\r\n\r\n`, or until EOF.
fn read_head<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(buf),
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    return Ok(buf);
                }
                if buf.len() > MAX_HEAD_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "head exceeds 64 KiB",
                    ));
                }
            }
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

fn read_line<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.len() > MAX_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk header exceeds 8 KiB",
            ));
        }
    }
}

enum Body {
    None,
    Length(u64),
    Chunked,
}

struct RequestHead {
    bytes: Vec<u8>,
    body: Body,
    expect_continue: bool,
    keep_alive: bool,
    is_head: bool,
}

#[derive(PartialEq)]
enum Framing {
    None,
    Length(u64),
    Chunked,
    Eof,
}

fn rewrite_request_head(head: &[u8]) -> RequestHead {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut body = Body::None;
    let mut expect_continue = false;
    let mut close = false;
    let mut forwarded = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("x-forwarded-proto:") {
            continue;
        }
        if let Some(value) = lower.strip_prefix("connection:") {
            close = value.contains("close");
            continue;
        }
        if let Some(value) = lower.strip_prefix("content-length:") {
            body = Body::Length(value.trim().parse().unwrap_or(0));
        }
        if let Some(value) = lower.strip_prefix("transfer-encoding:") {
            if value.contains("chunked") {
                body = Body::Chunked;
            }
        }
        if let Some(value) = lower.strip_prefix("expect:") {
            expect_continue = value.contains("100-continue");
        }
        forwarded.push_str(line);
        forwarded.push_str("\r\n");
    }
    let mut bytes = Vec::with_capacity(forwarded.len() + 64);
    bytes.extend_from_slice(request_line.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(forwarded.as_bytes());
    bytes.extend_from_slice(b"X-Forwarded-Proto: https\r\n");
    bytes.extend_from_slice(b"Connection: close\r\n\r\n");
    let is_head = request_line
        .split_whitespace()
        .next()
        .map(|method| method.eq_ignore_ascii_case("HEAD"))
        .unwrap_or(false);
    RequestHead {
        bytes,
        body,
        expect_continue,
        keep_alive: request_line.ends_with("HTTP/1.1") && !close,
        is_head,
    }
}

fn response_framing(head: &[u8], is_head: bool) -> Framing {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or("");
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    if is_head || code == 204 || code == 304 {
        return Framing::None;
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().ok();
        } else if let Some(value) = lower.strip_prefix("transfer-encoding:") {
            chunked = chunked || value.contains("chunked");
        }
    }
    if chunked {
        Framing::Chunked
    } else if let Some(length) = length {
        Framing::Length(length)
    } else {
        Framing::Eof
    }
}

fn rewrite_response_head(
    tls: &StreamOwned<ServerConnection, TcpStream>,
    head: &[u8],
    keep_alive: bool,
) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or("");
    let (version, cipher, alpn) = negotiated_params(tls);

    let mut out = String::from(status);
    out.push_str("\r\n");
    let mut expose: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.to_ascii_lowercase().starts_with("connection:") {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("access-control-expose-headers") {
                expose = Some(value.trim().to_string());
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str(&format!("X-Negotiated-Version: {version}\r\n"));
    out.push_str(&format!("X-Negotiated-Cipher: {cipher}\r\n"));
    out.push_str(&format!("X-Negotiated-ALPN: {alpn}\r\n"));

    let mut exposed = expose.unwrap_or_default();
    for name in ["X-Negotiated-Version", "X-Negotiated-Cipher", "X-Negotiated-ALPN"] {
        if !exposed.to_ascii_lowercase().contains(&name.to_ascii_lowercase()) {
            if !exposed.is_empty() {
                exposed.push_str(", ");
            }
            exposed.push_str(name);
        }
    }
    out.push_str(&format!("Access-Control-Expose-Headers: {exposed}\r\n"));
    out.push_str(if keep_alive {
        "Connection: keep-alive\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    out.into_bytes()
}

fn build_listener(spec: &ListenerSpec) -> Result<ListenerRuntime> {
    let provider = build_provider(spec.provider.as_deref())?;
    let mut profiles = HashMap::new();
    for (name, profile) in &spec.profiles {
        profiles.insert(
            name.clone(),
            Arc::new(build_server_config(profile, provider.clone())?),
        );
    }
    Ok(ListenerRuntime {
        backend: spec.backend.clone(),
        default_profile: spec.default_profile.clone(),
        profiles,
    })
}

fn build_provider(kind: Option<&str>) -> Result<Arc<CryptoProvider>> {
    match kind.unwrap_or("aws-lc-rs") {
        "aws-lc-rs" | "aws_lc_rs" => Ok(Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
        "ring" => Ok(Arc::new(rustls::crypto::ring::default_provider())),
        other => Err(format!("unknown provider {other:?}").into()),
    }
}

fn build_server_config(spec: &ProfileSpec, provider: Arc<CryptoProvider>) -> Result<ServerConfig> {
    let versions = protocol_versions(spec)?;
    let provider = restrict_ciphers(provider, spec);
    let builder =
        ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(&versions)?;

    let certs = load_certs(&spec.cert)?;
    let key = load_key(&spec.key)?;

    let mut config = match spec.client_auth {
        ClientAuth::None => builder.with_no_client_auth().with_single_cert(certs, key)?,
        mode => {
            let ca = spec
                .client_ca
                .as_ref()
                .ok_or("client_auth requires client_ca")?;
            let roots = Arc::new(load_roots(ca)?);
            let verifier = WebPkiClientVerifier::builder_with_provider(roots, provider);
            let verifier = if mode == ClientAuth::Request {
                verifier.allow_unauthenticated().build()?
            } else {
                verifier.build()?
            };
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)?
        }
    };

    config.alpn_protocols = spec.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    config.max_early_data_size = spec.max_early_data;
    if let Some(tickets) = spec.tls13_tickets {
        config.send_tls13_tickets = tickets;
    }
    Ok(config)
}

fn protocol_versions(spec: &ProfileSpec) -> Result<Vec<&'static SupportedProtocolVersion>> {
    let min = spec.min_version.as_deref().unwrap_or("1.2");
    let max = spec.max_version.as_deref().unwrap_or("1.3");
    let known = ["1.2", "1.3"];
    let lo = known
        .iter()
        .position(|v| *v == min)
        .ok_or_else(|| format!("unknown min_version {min:?}"))?;
    let hi = known
        .iter()
        .position(|v| *v == max)
        .ok_or_else(|| format!("unknown max_version {max:?}"))?;
    if lo > hi {
        return Err(format!("min_version {min:?} > max_version {max:?}").into());
    }
    Ok(known[lo..=hi]
        .iter()
        .map(|v| match *v {
            "1.2" => &rustls::version::TLS12,
            _ => &rustls::version::TLS13,
        })
        .collect())
}

fn restrict_ciphers(provider: Arc<CryptoProvider>, spec: &ProfileSpec) -> Arc<CryptoProvider> {
    if spec.cipher_suites.is_none() && spec.key_exchange.is_none() {
        return provider;
    }
    let mut owned = (*provider).clone();
    if let Some(allowed) = &spec.cipher_suites {
        owned
            .cipher_suites
            .retain(|suite| allowed.iter().any(|name| name == &suite_name(suite)));
    }
    if let Some(allowed) = &spec.key_exchange {
        owned.kx_groups.retain(|group| {
            let name = format!("{:?}", group.name());
            allowed.iter().any(|allowed| allowed == &name)
        });
    }
    Arc::new(owned)
}

fn suite_name(suite: &rustls::SupportedCipherSuite) -> String {
    format!("{:?}", suite.suite())
}

/// HTTP/2 termination: one non-blocking event loop serves every stream on the
/// connection, translating each request to HTTP/1.1 against the backend and
/// streaming the response back as it arrives.
fn serve_h2(tls: StreamOwned<ServerConnection, TcpStream>, backend: &str) -> io::Result<()> {
    tls.sock.set_nonblocking(true)?;
    let negotiated = negotiated_params(&tls);
    let waker = std::task::Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut connection: h2::server::Connection<_, Bytes> =
        drive(h2::server::handshake(BlockingIo(tls))).map_err(io::Error::other)?;
    let mut streams: Vec<H2Stream> = Vec::new();
    loop {
        let mut progressed = false;
        let accepted = {
            let mut accept = std::pin::pin!(connection.accept());
            accept.as_mut().poll(&mut context)
        };
        match accepted {
            Poll::Ready(Some(Ok((request, respond)))) => {
                streams.push(H2Stream::new(request, respond, backend, &negotiated));
                progressed = true;
            }
            Poll::Ready(Some(Err(err))) => return Err(io::Error::other(err)),
            Poll::Ready(None) => return Ok(()),
            Poll::Pending => {}
        }
        streams.retain_mut(|stream| match stream.poll(&mut context) {
            Step::Progress => {
                progressed = true;
                true
            }
            Step::Idle => true,
            Step::Done => false,
        });
        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }
}

struct NoopWake;

impl std::task::Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

/// Minimal executor for the h2 handshake future and the per-stream body reads:
/// poll, and on `Pending` sleep briefly and re-poll.
fn drive<F: Future>(future: F) -> F::Output {
    let waker = std::task::Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

enum Step {
    Progress,
    Idle,
    Done,
}

enum Phase {
    Read,
    Write,
    Head,
    Body,
}

struct H2Stream {
    parts: http::request::Parts,
    body: RecvStream,
    body_bytes: Vec<u8>,
    request: Vec<u8>,
    written: usize,
    backend_address: String,
    backend: Option<TcpStream>,
    received: Vec<u8>,
    respond: SendResponse<Bytes>,
    send: Option<SendStream<Bytes>>,
    negotiated: (String, String, String),
    phase: Phase,
}

impl H2Stream {
    fn new(
        request: http::Request<RecvStream>,
        respond: SendResponse<Bytes>,
        backend: &str,
        negotiated: &(String, String, String),
    ) -> H2Stream {
        let (parts, body) = request.into_parts();
        H2Stream {
            parts,
            body,
            body_bytes: Vec::new(),
            request: Vec::new(),
            written: 0,
            backend_address: backend.to_string(),
            backend: None,
            received: Vec::new(),
            respond,
            send: None,
            negotiated: negotiated.clone(),
            phase: Phase::Read,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Step {
        match self.phase {
            Phase::Read => self.read_body(cx),
            Phase::Write => self.write_request(),
            Phase::Head => self.read_response_head(),
            Phase::Body => self.stream_body(),
        }
    }

    fn read_body(&mut self, cx: &mut Context<'_>) -> Step {
        let next = {
            let mut data = std::pin::pin!(self.body.data());
            match data.as_mut().poll(cx) {
                Poll::Ready(next) => next,
                Poll::Pending => return Step::Idle,
            }
        };
        match next {
            Some(Ok(chunk)) => {
                self.body_bytes.extend_from_slice(&chunk);
                Step::Progress
            }
            Some(Err(err)) => self.fail(&format!("request body: {err}")),
            None => self.start_backend(),
        }
    }

    fn start_backend(&mut self) -> Step {
        let authority = self
            .parts
            .uri
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "localhost".to_string());
        let path = self
            .parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        let mut head = format!("{} {} HTTP/1.1\r\n", self.parts.method, path);
        let mut has_host = false;
        for (name, value) in self.parts.headers.iter() {
            let name = name.as_str();
            if name.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "connection" | "content-length" | "transfer-encoding" | "keep-alive"
            ) {
                continue;
            }
            head.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap_or("")));
        }
        if !has_host {
            head.push_str(&format!("Host: {authority}\r\n"));
        }
        if !self.body_bytes.is_empty() {
            head.push_str(&format!("Content-Length: {}\r\n", self.body_bytes.len()));
        }
        head.push_str("X-Forwarded-Proto: https\r\nConnection: close\r\n\r\n");
        self.request = head.into_bytes();
        self.request.extend_from_slice(&self.body_bytes);

        let backend = match TcpStream::connect(&self.backend_address) {
            Ok(backend) => backend,
            Err(err) => {
                eprintln!("wpt-tls-server: backend connect failed: {err}");
                return self.send_bad_gateway();
            }
        };
        if let Err(err) = backend.set_nonblocking(true) {
            return self.fail(&format!("backend: {err}"));
        }
        self.backend = Some(backend);
        self.phase = Phase::Write;
        Step::Progress
    }

    fn write_request(&mut self) -> Step {
        let Some(backend) = self.backend.as_mut() else {
            return Step::Done;
        };
        let result = backend.write(&self.request[self.written..]);
        match result {
            Ok(0) => self.fail("backend closed while writing the request"),
            Ok(wrote) => {
                self.written += wrote;
                if self.written == self.request.len() {
                    self.phase = Phase::Head;
                }
                Step::Progress
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Step::Idle,
            Err(err) => self.fail(&format!("backend write: {err}")),
        }
    }

    fn read_response_head(&mut self) -> Step {
        if let Some(end) = self.received.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = self.received.drain(..end + 4).collect::<Vec<u8>>();
            return self.send_response_head(&head);
        }
        let Some(backend) = self.backend.as_mut() else {
            return Step::Done;
        };
        let mut buffer = [0u8; COPY_CHUNK];
        let result = backend.read(&mut buffer);
        match result {
            Ok(0) => self.fail("backend closed before the response head"),
            Ok(read) => {
                self.received.extend_from_slice(&buffer[..read]);
                if self.received.len() > MAX_HEAD_BYTES {
                    return self.fail("response head exceeds 64 KiB");
                }
                Step::Progress
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Step::Idle,
            Err(err) => self.fail(&format!("backend read: {err}")),
        }
    }

    fn send_response_head(&mut self, head: &[u8]) -> Step {
        let text = String::from_utf8_lossy(head);
        let mut lines = text.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(502);
        let mut builder = http::Response::builder().status(status);
        for line in lines {
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "connection" | "content-length" | "transfer-encoding" | "keep-alive"
            ) {
                continue;
            }
            builder = builder.header(name, value.trim());
        }
        let builder = builder
            .header("x-negotiated-version", &self.negotiated.0)
            .header("x-negotiated-cipher", &self.negotiated.1)
            .header("x-negotiated-alpn", &self.negotiated.2);
        let Ok(response) = builder.body(()) else {
            return self.fail("invalid response head from the backend");
        };
        match self.respond.send_response(response, false) {
            Ok(send) => {
                self.send = Some(send);
                self.phase = Phase::Body;
                Step::Progress
            }
            Err(err) => self.fail(&format!("h2 response: {err}")),
        }
    }

    fn stream_body(&mut self) -> Step {
        if self.received.is_empty() {
            let Some(backend) = self.backend.as_mut() else {
                return Step::Done;
            };
            let mut buffer = [0u8; COPY_CHUNK];
            let result = backend.read(&mut buffer);
            match result {
                Ok(0) => return self.finish_body(),
                Ok(read) => self.received.extend_from_slice(&buffer[..read]),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Step::Idle,
                Err(err) => return self.fail(&format!("backend read: {err}")),
            }
        }
        let take = self.received.len().min(COPY_CHUNK);
        let chunk = Bytes::from(self.received.drain(..take).collect::<Vec<u8>>());
        let Some(send) = self.send.as_mut() else {
            return Step::Done;
        };
        match send.send_data(chunk, false) {
            Ok(()) => Step::Progress,
            Err(err) => self.fail(&format!("h2 data: {err}")),
        }
    }

    fn finish_body(&mut self) -> Step {
        let Some(send) = self.send.as_mut() else {
            return Step::Done;
        };
        match send.send_data(Bytes::new(), true) {
            Ok(()) => Step::Done,
            Err(err) => self.fail(&format!("h2 data: {err}")),
        }
    }

    fn send_bad_gateway(&mut self) -> Step {
        let mut response = http::Response::new(());
        *response.status_mut() = http::StatusCode::BAD_GATEWAY;
        match self.respond.send_response(response, true) {
            Ok(_) => Step::Done,
            Err(err) => self.fail(&format!("h2 response: {err}")),
        }
    }

    fn fail(&self, message: &str) -> Step {
        eprintln!("wpt-tls-server: h2 stream: {message}");
        Step::Done
    }
}

/// Adapter that gives the `h2` state machine tokio's async I/O traits backed by
/// the rustls stream on the connection's own thread, where `poll_*` may block.
struct BlockingIo<T>(T);

impl<T: Read + Unpin> AsyncRead for BlockingIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let dst = buf.initialize_unfilled();
            if dst.is_empty() {
                return Poll::Ready(Ok(()));
            }
            match this.0.read(dst) {
                Ok(0) => {
                    return Poll::Ready(Ok(()));
                }
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(err) => {
                    eprintln!("wpt-tls-server: poll_read error {err}");
                    return Poll::Ready(Err(err));
                }
            }
        }
    }
}

impl<T: Write + Unpin> AsyncWrite for BlockingIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut().0.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().0.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().0.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let data = fs::read(path)?;
    let mut reader = BufReader::new(&data[..]);
    Ok(rustls_pemfile::certs(&mut reader).collect::<io::Result<Vec<_>>>()?)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let data = fs::read(path)?;
    let mut reader = BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| "no private key found".into())
}

fn load_roots(path: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(path)? {
        roots.add(cert)?;
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::ensure_loopback;

    #[test]
    fn accepts_loopback_addresses() {
        assert!(ensure_loopback("127.0.0.1:8447", "listen address").is_ok());
        assert!(ensure_loopback("[::1]:8447", "listen address").is_ok());
        assert!(ensure_loopback("localhost:8000", "backend address").is_ok());
    }

    #[test]
    fn rejects_routable_addresses() {
        assert!(ensure_loopback("0.0.0.0:8447", "listen address").is_err());
        assert!(ensure_loopback("192.0.2.1:8000", "backend address").is_err());
    }

    #[test]
    fn rejects_unparsable_addresses() {
        assert!(ensure_loopback("not an address", "listen address").is_err());
    }
}
