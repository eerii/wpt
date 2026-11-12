mod common;

use common::*;
use rcgen::KeyPair;
use wpt_tls_server::ClientAuth;

#[test]
fn version_pinning_rejects_older_client() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.min_version = Some("1.3".into());
    p.max_version = Some("1.3".into());
    let (_running, addr) = run(config(p, backend));

    let client = make_client(&[&rustls::version::TLS12], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect(addr, client).unwrap();
    assert!(
        http_get(&mut tls).is_err(),
        "TLS 1.2 client must fail against TLS 1.3-only server"
    );
}

#[test]
fn version_pinning_accepts_matching_client() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.min_version = Some("1.3".into());
    p.max_version = Some("1.3".into());
    let (_running, addr) = run(config(p, backend));

    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect(addr, client).unwrap();
    let response = http_get(&mut tls).unwrap();
    assert_eq!(header(&response, "X-Negotiated-Version"), Some("TLSv1_3"));
}

#[test]
fn tls12_only_server_negotiates_tls12() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.min_version = Some("1.2".into());
    p.max_version = Some("1.2".into());
    let (_running, addr) = run(config(p, backend));

    let client = make_client(
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        roots(&pki.ca_der),
        &[],
        None,
        None,
    );
    let mut tls = connect(addr, client).unwrap();
    let response = http_get(&mut tls).unwrap();
    assert_eq!(header(&response, "X-Negotiated-Version"), Some("TLSv1_2"));
}

#[test]
fn alpn_is_negotiated_and_reported() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.alpn = vec!["h2".into(), "http/1.1".into()];
    let (_running, addr) = run(config(p, backend));

    // The prototype does not serve h2 yet, so assert with http/1.1 while
    // advertising h2 and confirm the server reports the negotiated choice.
    let client = make_client(
        &[&rustls::version::TLS13],
        roots(&pki.ca_der),
        &[b"http/1.1"],
        None,
        None,
    );
    let mut tls = connect(addr, client).unwrap();
    let response = http_get(&mut tls).unwrap();
    assert_eq!(header(&response, "X-Negotiated-ALPN"), Some("http/1.1"));
}

#[test]
fn alpn_without_overlap_fails_handshake() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.alpn = vec!["h2".into()];
    let (_running, addr) = run(config(p, backend));

    let client = make_client(
        &[&rustls::version::TLS13],
        roots(&pki.ca_der),
        &[b"http/1.1"],
        None,
        None,
    );
    let mut tls = connect(addr, client).unwrap();
    assert!(
        http_get(&mut tls).is_err(),
        "no ALPN overlap should abort the handshake"
    );
}

#[test]
fn cipher_suites_can_be_pinned() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.min_version = Some("1.3".into());
    p.max_version = Some("1.3".into());
    p.cipher_suites = Some(vec!["TLS13_CHACHA20_POLY1305_SHA256".into()]);
    let (_running, addr) = run(config(p, backend));

    // Client only offers AES-128-GCM: no shared suite, handshake must fail.
    let client = make_client(
        &[&rustls::version::TLS13],
        roots(&pki.ca_der),
        &[],
        None,
        Some(&["TLS13_AES_128_GCM_SHA256"]),
    );
    let mut tls = connect(addr, client).unwrap();
    assert!(http_get(&mut tls).is_err(), "disjoint cipher sets must fail");

    // Now pin the server to the suite the client offers: succeeds and is reported.
    let mut p2 = profile(&pki);
    p2.min_version = Some("1.3".into());
    p2.max_version = Some("1.3".into());
    p2.cipher_suites = Some(vec!["TLS13_AES_128_GCM_SHA256".into()]);
    let (_running2, addr2) = run(config(p2, backend));
    let client = make_client(
        &[&rustls::version::TLS13],
        roots(&pki.ca_der),
        &[],
        None,
        Some(&["TLS13_AES_128_GCM_SHA256"]),
    );
    let mut tls = connect(addr2, client).unwrap();
    let response = http_get(&mut tls).unwrap();
    assert_eq!(
        header(&response, "X-Negotiated-Cipher"),
        Some("TLS13_AES_128_GCM_SHA256")
    );
}

#[test]
fn client_cert_required_rejects_anonymous() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.client_auth = ClientAuth::Require;
    p.client_ca = Some(write_tmp("ca.pem", &pki.ca_pem));
    let (_running, addr) = run(config(p, backend));

    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect(addr, client).unwrap();
    assert!(
        http_get(&mut tls).is_err(),
        "server requires a client certificate"
    );
}

#[test]
fn client_cert_required_accepts_valid_cert() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.client_auth = ClientAuth::Require;
    p.client_ca = Some(write_tmp("ca.pem", &pki.ca_pem));
    let (_running, addr) = run(config(p, backend));

    let identity = (
        pem_certs(&pki.client_cert_pem),
        pem_key(&pki.client_key_pem),
    );
    let client = make_client(
        &[&rustls::version::TLS13],
        roots(&pki.ca_der),
        &[],
        Some(identity),
        None,
    );
    let mut tls = connect(addr, client).unwrap();
    let response = http_get(&mut tls).unwrap();
    assert_eq!(header(&response, "X-Negotiated-Version"), Some("TLSv1_3"));
}

#[test]
fn client_cert_optional_accepts_anonymous_and_certified() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.client_auth = ClientAuth::Request;
    p.client_ca = Some(write_tmp("ca.pem", &pki.ca_pem));
    let (_running, addr) = run(config(p, backend));

    // Anonymous is allowed in optional mode.
    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect(addr, client).unwrap();
    assert!(http_get(&mut tls).is_ok());

    // A valid certificate is also accepted.
    let identity = (
        pem_certs(&pki.client_cert_pem),
        pem_key(&pki.client_key_pem),
    );
    let client = make_client(
        &[&rustls::version::TLS13],
        roots(&pki.ca_der),
        &[],
        Some(identity),
        None,
    );
    let mut tls = connect(addr, client).unwrap();
    assert!(http_get(&mut tls).is_ok());
}

#[test]
fn forwards_proto_and_reports_negotiated_parameters() {
    let pki = Pki::generate();
    let backend = start_backend();
    let (_running, addr) = run(config(profile(&pki), backend));

    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect(addr, client).unwrap();
    // Client tries to lie about the scheme; the sidecar must override it.
    let response = http_request(&mut tls, "X-Forwarded-Proto: http\r\n").unwrap();

    let seen = body(&response).to_ascii_lowercase();
    assert!(seen.contains("x-forwarded-proto: https"), "backend saw: {seen}");
    assert!(
        !seen.contains("x-forwarded-proto: http\r\n"),
        "client-supplied value not stripped"
    );
    assert!(
        seen.contains("connection: close\r\n"),
        "backend connection is bounded so the response can be framed"
    );
    assert_eq!(header(&response, "X-Negotiated-Version"), Some("TLSv1_3"));
    assert!(header(&response, "X-Negotiated-Cipher").is_some());
}

#[test]
fn sni_selects_profile_by_name() {
    let pki = Pki::generate();
    let backend = start_backend();

    // "one" is TLS 1.3-only; "two" is TLS 1.2-only. Same port, same listener.
    let one_key = KeyPair::generate().unwrap();
    let mut one = profile_with_cert(
        &pki.issue(server_params_for("one"), &one_key),
        &one_key.serialize_pem(),
    );
    one.min_version = Some("1.3".into());
    one.max_version = Some("1.3".into());

    let two_key = KeyPair::generate().unwrap();
    let mut two = profile_with_cert(
        &pki.issue(server_params_for("two"), &two_key),
        &two_key.serialize_pem(),
    );
    two.min_version = Some("1.2".into());
    two.max_version = Some("1.2".into());

    let cfg = config_with_profiles(vec![("one", one), ("two", two)], backend, None);
    let (_running, addr) = run(cfg);

    // SNI "one" gets the TLS 1.3-only profile.
    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect_named(addr, client, "one").unwrap();
    let response = http_get(&mut tls).unwrap();
    assert_eq!(header(&response, "X-Negotiated-Version"), Some("TLSv1_3"));

    // SNI "two" gets the TLS 1.2-only profile, on the same port.
    let client = make_client(
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        roots(&pki.ca_der),
        &[],
        None,
        None,
    );
    let mut tls = connect_named(addr, client, "two").unwrap();
    let response = http_get(&mut tls).unwrap();
    assert_eq!(header(&response, "X-Negotiated-Version"), Some("TLSv1_2"));

    // A TLS 1.3 client against "two" (1.2-only) fails.
    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect_named(addr, client, "two").unwrap();
    assert!(http_get(&mut tls).is_err());
}
