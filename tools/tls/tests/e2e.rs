mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};

use common::*;
use rcgen::KeyPair;
use serde_json::{json, Map, Value};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Drives the compiled `wpt-tls-server` binary through its JSON config with
/// three SNI profiles on one listener, proving the subprocess/knob-interface
/// path and SNI-based profile selection.
#[test]
fn binary_serves_multiple_profiles_from_json() {
    let pki = Pki::generate();
    let backend = start_backend();

    let mut profiles: Map<String, Value> = Map::new();
    for (name, min, max) in [("v13", "1.3", "1.3"), ("v12", "1.2", "1.2")] {
        let key = KeyPair::generate().unwrap();
        let cert = pki.issue(server_params_for(name), &key);
        profiles.insert(
            name.to_string(),
            json!({
                "cert": write_tmp(&format!("{name}.pem"), &cert),
                "key": write_tmp(&format!("{name}.key"), &key.serialize_pem()),
                "min_version": min,
                "max_version": max,
            }),
        );
    }

    let cauth_key = KeyPair::generate().unwrap();
    let cauth_cert = pki.issue(server_params_for("cauth"), &cauth_key);
    profiles.insert(
        "cauth".to_string(),
        json!({
            "cert": write_tmp("cauth.pem", &cauth_cert),
            "key": write_tmp("cauth.key", &cauth_key.serialize_pem()),
            "client_auth": "require",
            "client_ca": write_tmp("ca.pem", &pki.ca_pem),
        }),
    );

    let config = json!({
        "listeners": [{
            "listen": "127.0.0.1:0",
            "backend": backend.to_string(),
            "default_profile": "v13",
            "profiles": profiles,
        }]
    });
    let config_path = write_tmp("config.json", &config.to_string());

    let mut child = Command::new(env!("CARGO_BIN_EXE_wpt-tls-server"))
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to start wpt-tls-server");

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("server died before listening");
    let addr: SocketAddr = line
        .trim()
        .rsplit(" on ")
        .next()
        .expect("unexpected output")
        .parse()
        .unwrap();
    let _guard = ChildGuard(child);

    // SNI "v13" rejects a TLS 1.2 client, accepts TLS 1.3.
    let client = make_client(&[&rustls::version::TLS12], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect_named(addr, client, "v13").unwrap();
    assert!(http_get(&mut tls).is_err());

    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect_named(addr, client, "v13").unwrap();
    let response = http_get(&mut tls).unwrap();
    assert_eq!(header(&response, "X-Negotiated-Version"), Some("TLSv1_3"));

    // SNI "v12" negotiates TLS 1.2 with a default client.
    let client = make_client(
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        roots(&pki.ca_der),
        &[],
        None,
        None,
    );
    let mut tls = connect_named(addr, client, "v12").unwrap();
    let response = http_get(&mut tls).unwrap();
    assert_eq!(header(&response, "X-Negotiated-Version"), Some("TLSv1_2"));

    // SNI "cauth" rejects an anonymous client.
    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect_named(addr, client, "cauth").unwrap();
    assert!(http_get(&mut tls).is_err());
}
