//! Proof-of-concept TLS sidecar for web-platform-tests.
//!
//! Terminates TLS (selecting a per-SNI profile) and forwards the request to a
//! backend (wptserve) over loopback, terminating HTTP/2 and translating it to
//! HTTP/1.1. The negotiated parameters are echoed back as `X-Negotiated-*`
//! response headers so tests can assert on them.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
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
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{Acceptor, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned, SupportedProtocolVersion};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listeners: Vec<ListenerSpec>,
}

#[derive(Debug, Clone, Deserialize)]
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
    let head = read_head(tls)?;
    if head.is_empty() {
        return Ok(());
    }
    let (head, content_length) = rewrite_request_head(&head);

    let mut backend = TcpStream::connect(backend)?;
    backend.write_all(&head)?;
    if content_length > 0 {
        io::copy(&mut (&mut *tls).take(content_length), &mut backend)?;
    }

    let response_head = read_head(&mut backend)?;
    let response_head = inject_negotiated_headers(tls, &response_head);
    tls.write_all(&response_head)?;
    io::copy(&mut backend, tls)?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
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
            }
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

/// Strip any client-supplied `X-Forwarded-Proto`/`Connection`, force
/// `Connection: close`, and return the request head plus its declared body
/// length.
fn rewrite_request_head(head: &[u8]) -> (Vec<u8>, u64) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut content_length = 0u64;
    let mut forwarded = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("x-forwarded-proto:") || lower.starts_with("connection:") {
            continue;
        }
        if lower.starts_with("content-length:") {
            content_length = line[15..].trim().parse().unwrap_or(0);
        }
        forwarded.push_str(line);
        forwarded.push_str("\r\n");
    }
    let mut out = Vec::with_capacity(forwarded.len() + 64);
    out.extend_from_slice(request_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(forwarded.as_bytes());
    out.extend_from_slice(b"X-Forwarded-Proto: https\r\n");
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    (out, content_length)
}

fn inject_negotiated_headers(
    tls: &StreamOwned<ServerConnection, TcpStream>,
    head: &[u8],
) -> Vec<u8> {
    if head.len() < 4 {
        return head.to_vec();
    }
    let (version, cipher, alpn) = negotiated_params(tls);

    let split = head.len() - 4;
    let mut out = head[..split].to_vec();
    out.extend_from_slice(format!("\r\nX-Negotiated-Version: {version}\r\n").as_bytes());
    out.extend_from_slice(format!("X-Negotiated-Cipher: {cipher}\r\n").as_bytes());
    out.extend_from_slice(format!("X-Negotiated-ALPN: {alpn}\r\n\r\n").as_bytes());
    out
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
    let Some(allowed) = &spec.cipher_suites else {
        return provider;
    };
    let mut owned = (*provider).clone();
    owned
        .cipher_suites
        .retain(|suite| allowed.iter().any(|name| name == &suite_name(suite)));
    Arc::new(owned)
}

fn suite_name(suite: &rustls::SupportedCipherSuite) -> String {
    format!("{:?}", suite.suite())
}

/// HTTP/2 termination: accept h2 streams and serve each one as an HTTP/1.1
/// request against the backend, then translate the response back to h2.
///
/// The `h2` state machine is driven with `pollster::block_on` over a small
/// adapter that performs the (blocking) rustls I/O from `poll_read`/`poll_write`
/// on the connection's own thread. This is adequate for test traffic; a
/// production version would likely use a tokio runtime.
fn serve_h2(tls: StreamOwned<ServerConnection, TcpStream>, backend: &str) -> io::Result<()> {
    tls.sock.set_nonblocking(true)?;
    let negotiated = negotiated_params(&tls);
    let mut conn: h2::server::Connection<_, Bytes> =
        drive(h2::server::handshake(BlockingIo(tls))).map_err(io::Error::other)?;
    while let Some(request) = drive(conn.accept()) {
        let (request, respond) = request.map_err(io::Error::other)?;
        if let Err(err) = handle_h2_stream(request, respond, backend, &negotiated) {
            eprintln!("wpt-tls-server: h2 stream error: {err}");
        }
    }
    Ok(())
}

/// Minimal executor for the h2 futures: poll, and on `Pending` sleep briefly and
/// re-poll. Combined with the non-blocking adapter below, this lets h2's
/// read-ahead return control so `accept()` can hand back queued streams.
fn drive<F: std::future::Future>(future: F) -> F::Output {
    struct NoopWake;
    impl std::task::Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }
    let waker = std::task::Waker::from(Arc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn handle_h2_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    backend: &str,
    negotiated: &(String, String, String),
) -> io::Result<()> {
    let (parts, _body) = request.into_parts();
    let authority = parts
        .uri
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "localhost".to_string());
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let mut h1 = format!("{} {} HTTP/1.1\r\n", parts.method, path);
    let mut has_host = false;
    for (name, value) in parts.headers.iter() {
        let name = name.as_str();
        if name.starts_with(':') || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        h1.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap_or("")));
    }
    if !has_host {
        h1.push_str(&format!("Host: {authority}\r\n"));
    }
    h1.push_str("X-Forwarded-Proto: https\r\nConnection: close\r\n\r\n");

    let mut backend_stream = TcpStream::connect(backend)?;
    backend_stream.write_all(h1.as_bytes())?;

    let head = read_head(&mut backend_stream)?;
    let text = String::from_utf8_lossy(&head);
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
        if let Some((key, value)) = line.split_once(':') {
            let lower = key.trim().to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "connection" | "content-length" | "transfer-encoding" | "keep-alive"
            ) {
                continue;
            }
            builder = builder.header(key.trim(), value.trim());
        }
    }
    builder = builder.header("x-negotiated-version", &negotiated.0);
    builder = builder.header("x-negotiated-cipher", &negotiated.1);
    builder = builder.header("x-negotiated-alpn", &negotiated.2);
    let response = builder.body(()).map_err(io::Error::other)?;

    let mut body = Vec::new();
    io::copy(&mut backend_stream, &mut body)?;

    let mut stream = respond.send_response(response, false).map_err(io::Error::other)?;
    stream
        .send_data(Bytes::from(body), true)
        .map_err(io::Error::other)?;
    Ok(())
}

/// Adapter that gives the `h2` state machine tokio's async I/O traits backed by
/// the blocking rustls stream. Blocking in `poll_*` is safe here because each
/// connection runs on its own thread and is driven with `pollster::block_on`.
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
