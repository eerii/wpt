mod common;

use std::io::{Read, Write};

use rustls::{ClientConnection, StreamOwned};
use std::net::{SocketAddr, TcpListener};
use std::thread;

use common::*;

fn start_body_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(head) = read_head(&mut stream) else { continue };
            let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
            let mut payload = Vec::new();
            if head.contains("transfer-encoding: chunked") {
                loop {
                    let mut line = Vec::new();
                    while !line.ends_with(b"\r\n") {
                        let mut byte = [0u8; 1];
                        if stream.read_exact(&mut byte).is_err() {
                            break;
                        }
                        line.push(byte[0]);
                    }
                    let field = String::from_utf8_lossy(&line).trim().to_string();
                    let size = usize::from_str_radix(field.split(';').next().unwrap_or(""), 16)
                        .unwrap_or(0);
                    if size == 0 {
                        break;
                    }
                    let mut chunk = vec![0u8; size + 2];
                    stream.read_exact(&mut chunk).unwrap();
                    payload.extend_from_slice(&chunk[..size]);
                }
            } else if let Some(length) = header(&head, "content-length") {
                let mut chunk = vec![0u8; length.parse().unwrap_or(0)];
                stream.read_exact(&mut chunk).unwrap();
                payload = chunk;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                payload.len(),
                String::from_utf8_lossy(&payload)
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    addr
}

fn connect_for(
    pki: &Pki,
    addr: SocketAddr,
) -> StreamOwned<ClientConnection, std::net::TcpStream> {
    let client = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[], None, None);
    connect(addr, client).unwrap()
}

#[test]
fn keep_alive_serves_two_requests_on_one_connection() {
    let pki = Pki::generate();
    let (_running, addr) = run(config(profile(&pki), start_backend()));
    let mut tls = connect_for(&pki, addr);

    tls.write_all(b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let first = read_head(&mut tls).unwrap();
    let first = String::from_utf8_lossy(&first).into_owned();
    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    assert_eq!(header(&first, "Connection"), Some("keep-alive"));
    let length: usize = header(&first, "Content-Length").unwrap().parse().unwrap();
    let mut first_body = vec![0u8; length];
    tls.read_exact(&mut first_body).unwrap();

    tls.write_all(b"GET /two HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut rest = Vec::new();
    tls.read_to_end(&mut rest).unwrap();
    let rest = String::from_utf8_lossy(&rest).into_owned();
    assert!(rest.starts_with("HTTP/1.1 200"), "{rest}");
    assert!(rest.contains("/two"), "second request reached the backend");
}

#[test]
fn chunked_request_body_is_forwarded() {
    let pki = Pki::generate();
    let (_running, addr) = run(config(profile(&pki), start_body_backend()));
    let mut tls = connect_for(&pki, addr);

    tls.write_all(
        b"POST /chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
          5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .unwrap();
    let mut out = Vec::new();
    tls.read_to_end(&mut out).unwrap();
    let out = String::from_utf8_lossy(&out).into_owned();
    assert_eq!(body(&out), "hello world");
}

#[test]
fn expect_continue_is_answered_before_the_body() {
    let pki = Pki::generate();
    let (_running, addr) = run(config(profile(&pki), start_body_backend()));
    let mut tls = connect_for(&pki, addr);

    tls.write_all(
        b"POST /continue HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\
          Expect: 100-continue\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let interim = read_head(&mut tls).unwrap();
    assert!(
        String::from_utf8_lossy(&interim).starts_with("HTTP/1.1 100 Continue"),
        "interim response must arrive before the body"
    );

    tls.write_all(b"hello").unwrap();
    let mut out = Vec::new();
    tls.read_to_end(&mut out).unwrap();
    assert_eq!(body(&String::from_utf8_lossy(&out)), "hello");
}

#[test]
fn unreachable_backend_answers_502() {
    let pki = Pki::generate();
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let (_running, addr) = run(config(profile(&pki), dead_addr));
    let mut tls = connect_for(&pki, addr);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out).into_owned();
    assert!(out.starts_with("HTTP/1.1 502"), "{out}");
}

#[test]
fn negotiated_headers_are_exposed_for_cross_origin_fetch() {
    let pki = Pki::generate();
    let (_running, addr) = run(config(profile(&pki), start_backend()));
    let mut tls = connect_for(&pki, addr);
    let response = http_get(&mut tls).unwrap();
    let exposed = header(&response, "Access-Control-Expose-Headers").unwrap_or("");
    assert!(exposed.contains("X-Negotiated-ALPN"), "{exposed}");
}
