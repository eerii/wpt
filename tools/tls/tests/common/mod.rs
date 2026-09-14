#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned, SupportedProtocolVersion,
};
use wpt_tls_server::{
    start, ClientAuth, Config, ListenerSpec, ProfileSpec, RunningServer,
};

static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A throwaway PKI: one CA plus a valid server and client leaf.
pub struct Pki {
    pub ca_pem: String,
    pub ca_der: CertificateDer<'static>,
    pub ca_cert: Certificate,
    pub ca_key: KeyPair,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

impl Pki {
    pub fn generate() -> Pki {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "wpt-tls-poc-ca");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let server_cert = server_params_for("localhost")
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "wpt-tls-poc-client");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        Pki {
            ca_pem: ca_cert.pem(),
            ca_der: ca_cert.der().clone(),
            ca_cert,
            ca_key,
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// Sign arbitrary parameters with this CA.
    pub fn issue(&self, params: CertificateParams, key: &KeyPair) -> String {
        params.signed_by(key, &self.ca_cert, &self.ca_key).unwrap().pem()
    }
}

/// A server leaf certificate for `name`, valid for server auth.
pub fn server_params_for(name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
}

/// The default valid server leaf for `localhost`.
pub fn server_params() -> CertificateParams {
    server_params_for("localhost")
}

pub fn write_tmp(name: &str, content: &str) -> String {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("wpt-tls-poc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{n}-{name}"));
    std::fs::write(&path, content).unwrap();
    path.to_string_lossy().into_owned()
}

/// A profile presenting `pki`'s valid `localhost` certificate.
pub fn profile(pki: &Pki) -> ProfileSpec {
    profile_with_cert(&pki.server_cert_pem, &pki.server_key_pem)
}

/// A profile presenting an arbitrary certificate chain.
pub fn profile_with_cert(cert_pem: &str, key_pem: &str) -> ProfileSpec {
    ProfileSpec {
        cert: write_tmp("server.pem", cert_pem),
        key: write_tmp("server.key", key_pem),
        min_version: None,
        max_version: None,
        alpn: Vec::new(),
        client_auth: ClientAuth::None,
        client_ca: None,
        cipher_suites: None,
    }
}

/// A single-listener config with one `default` profile.
pub fn config(profile: ProfileSpec, backend: SocketAddr) -> Config {
    config_with_profiles(vec![("default", profile)], backend, Some("default"))
}

/// A single-listener config with several named profiles (SNI-selectable).
pub fn config_with_profiles(
    profiles: Vec<(&str, ProfileSpec)>,
    backend: SocketAddr,
    default_profile: Option<&str>,
) -> Config {
    let profiles = profiles
        .into_iter()
        .map(|(name, profile)| (name.to_string(), profile))
        .collect::<HashMap<_, _>>();
    Config {
        listeners: vec![ListenerSpec {
            listen: "127.0.0.1:0".to_string(),
            backend: backend.to_string(),
            provider: None,
            default_profile: default_profile.map(str::to_string),
            profiles,
        }],
    }
}

/// A tiny HTTP/1.1 backend that echoes the request head back in the body.
pub fn start_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(head) = read_head(&mut stream) else { continue };
            let body = format!("BACKEND-SAW:\n{}", String::from_utf8_lossy(&head));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    addr
}

pub fn read_head<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
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

pub fn pem_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .collect::<io::Result<Vec<_>>>()
        .unwrap()
}

pub fn pem_key(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut BufReader::new(pem.as_bytes()))
        .unwrap()
        .unwrap()
}

pub fn roots(ca: &CertificateDer<'static>) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.add(ca.clone()).unwrap();
    store
}

pub fn make_client(
    versions: &[&'static SupportedProtocolVersion],
    roots: RootCertStore,
    alpn: &[&[u8]],
    identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    ciphers: Option<&[&str]>,
) -> Arc<ClientConfig> {
    let mut provider = rustls::crypto::ring::default_provider();
    if let Some(allowed) = ciphers {
        provider
            .cipher_suites
            .retain(|s| allowed.iter().any(|n| format!("{:?}", s.suite()) == *n));
    }
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots);
    let mut config = match identity {
        Some((cert, key)) => builder.with_client_auth_cert(cert, key).unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

pub fn connect(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    connect_named(addr, config, "localhost")
}

pub fn connect_named(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    name: &str,
) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let server_name = ServerName::try_from(name.to_string()).unwrap();
    let conn = ClientConnection::new(config, server_name).map_err(io::Error::other)?;
    let tcp = TcpStream::connect(addr)?;
    Ok(StreamOwned::new(conn, tcp))
}

pub fn http_get(tls: &mut StreamOwned<ClientConnection, TcpStream>) -> io::Result<String> {
    http_request(tls, "")
}

pub fn http_request(
    tls: &mut StreamOwned<ClientConnection, TcpStream>,
    extra: &str,
) -> io::Result<String> {
    let request = format!("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\r\n");
    tls.write_all(request.as_bytes())?;
    let mut out = Vec::new();
    tls.read_to_end(&mut out)?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

pub fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let head = response.split("\r\n\r\n").next()?;
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

pub fn body(response: &str) -> &str {
    response.splitn(2, "\r\n\r\n").nth(1).unwrap_or("")
}

pub fn run(config: Config) -> (RunningServer, SocketAddr) {
    let running = start(config).unwrap();
    let addr = running.addrs[0].1;
    (running, addr)
}
