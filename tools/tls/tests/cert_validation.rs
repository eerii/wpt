mod common;

use common::*;
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};

fn expect_handshake_failure(cert_pem: &str, key_pem: &str, pki: &Pki) {
    let backend = start_backend();
    let (_running, addr) = run(config(profile_with_cert(cert_pem, key_pem), backend));
    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect(addr, client).unwrap();
    assert!(http_get(&mut tls).is_err(), "handshake should have failed");
}

fn expect_handshake_success(cert_pem: &str, key_pem: &str, pki: &Pki) {
    let backend = start_backend();
    let (_running, addr) = run(config(profile_with_cert(cert_pem, key_pem), backend));
    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    let mut tls = connect(addr, client).unwrap();
    assert!(http_get(&mut tls).is_ok(), "handshake should have succeeded");
}

#[test]
fn self_signed_certificate_is_rejected() {
    let pki = Pki::generate();
    let key = KeyPair::generate().unwrap();
    let cert = server_params().self_signed(&key).unwrap();
    expect_handshake_failure(&cert.pem(), &key.serialize_pem(), &pki);
}

#[test]
fn certificate_from_untrusted_ca_is_rejected() {
    let pki = Pki::generate();
    let other = Pki::generate();
    let key = KeyPair::generate().unwrap();
    let cert = other.issue(server_params(), &key);
    expect_handshake_failure(&cert, &key.serialize_pem(), &pki);
}

#[test]
fn expired_certificate_is_rejected() {
    let pki = Pki::generate();
    let key = KeyPair::generate().unwrap();
    let mut params = server_params();
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2021, 1, 1);
    let cert = pki.issue(params, &key);
    expect_handshake_failure(&cert, &key.serialize_pem(), &pki);
}

#[test]
fn not_yet_valid_certificate_is_rejected() {
    let pki = Pki::generate();
    let key = KeyPair::generate().unwrap();
    let mut params = server_params();
    params.not_before = date_time_ymd(4090, 1, 1);
    params.not_after = date_time_ymd(4091, 1, 1);
    let cert = pki.issue(params, &key);
    expect_handshake_failure(&cert, &key.serialize_pem(), &pki);
}

#[test]
fn certificate_for_wrong_host_is_rejected() {
    let pki = Pki::generate();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["wrong.example".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = pki.issue(params, &key);
    expect_handshake_failure(&cert, &key.serialize_pem(), &pki);
}

#[test]
fn certificate_without_server_auth_eku_is_rejected() {
    let pki = Pki::generate();
    let key = KeyPair::generate().unwrap();
    let mut params = server_params();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = pki.issue(params, &key);
    expect_handshake_failure(&cert, &key.serialize_pem(), &pki);
}

#[test]
fn well_formed_chain_is_accepted() {
    let pki = Pki::generate();
    let key = KeyPair::generate().unwrap();
    let cert = pki.issue(server_params(), &key);
    expect_handshake_success(&cert, &key.serialize_pem(), &pki);
}

#[test]
fn full_chain_through_intermediate_is_accepted() {
    let pki = Pki::generate();

    let intermediate_key = KeyPair::generate().unwrap();
    let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "wpt-tls-poc-intermediate");
    let intermediate = intermediate_params
        .signed_by(&intermediate_key, &pki.ca_cert, &pki.ca_key)
        .unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let leaf = server_params()
        .signed_by(&leaf_key, &intermediate, &intermediate_key)
        .unwrap();

    // Server presents leaf first, then the intermediate; the client trusts the root.
    let chain = format!("{}{}", leaf.pem(), intermediate.pem());
    expect_handshake_success(&chain, &leaf_key.serialize_pem(), &pki);
}
