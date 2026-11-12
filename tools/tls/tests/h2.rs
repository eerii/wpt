mod common;

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wpt_tls_server::ProfileSpec;

/// Non-blocking adapter so the h2 client state machine can drive rustls I/O.
struct NonBlocking<T>(T);

impl<T: Read + Unpin> AsyncRead for NonBlocking<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let dst = buf.initialize_unfilled();
        if dst.is_empty() {
            return Poll::Ready(Ok(()));
        }
        match this.0.read(dst) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl<T: Write + Unpin> AsyncWrite for NonBlocking<T> {
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
        Poll::Ready(self.get_mut().0.flush())
    }
}

fn drive<F: Future>(future: F) -> F::Output {
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
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn h2_profile(pki: &Pki) -> ProfileSpec {
    let mut profile = profile(pki);
    profile.alpn = vec!["h2".into()];
    profile
}

/// Runs the h2 client connection on its own thread, which keeps I/O moving.
fn connect_h2(pki: &Pki, addr: SocketAddr) -> h2::client::SendRequest<Bytes> {
    let client_config = make_client(
        &[&rustls::version::TLS13],
        roots(&pki.ca_der),
        &[b"h2"],
        None,
        None,
    );
    let conn =
        ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap()).unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_nonblocking(true).unwrap();
    let (send_request, connection) = drive(h2::client::handshake(NonBlocking(StreamOwned::new(
        conn, tcp,
    ))))
    .unwrap();
    thread::spawn(move || {
        let _ = drive(connection);
    });
    send_request
}

fn get(path: &str) -> http::Request<()> {
    http::Request::builder()
        .method("GET")
        .uri(format!("https://localhost{path}"))
        .body(())
        .unwrap()
}

fn read_body(mut body: h2::RecvStream) -> Vec<u8> {
    let mut received = Vec::new();
    while let Some(chunk) = drive(body.data()) {
        received.extend_from_slice(&chunk.unwrap());
    }
    received
}

/// Answers every request with the request body it read.
fn start_echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(head) = read_head(&mut stream) else {
                continue;
            };
            let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
            let length = header(&head, "content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let mut payload = vec![0u8; length];
            if stream.read_exact(&mut payload).is_err() {
                continue;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&payload);
        }
    });
    addr
}

/// Answers every request with `size` bytes of recognisable filler.
fn start_large_backend(size: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(head) = read_head(&mut stream) else {
                continue;
            };
            if head.is_empty() {
                continue;
            }
            let payload: Vec<u8> = (0..size).map(|index| b'a' + (index % 26) as u8).collect();
            let response =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&payload);
        }
    });
    addr
}

/// Withholds every answer until two requests are in flight, so only a server
/// that interleaves its streams can complete them.
fn start_gated_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let arrived = Arc::new((Mutex::new(0usize), Condvar::new()));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(head) = read_head(&mut stream) else {
                continue;
            };
            let arrived = arrived.clone();
            thread::spawn(move || {
                let (count, ready) = &*arrived;
                let mut count = count.lock().unwrap();
                *count += 1;
                ready.notify_all();
                while *count < 2 {
                    let (guard, timeout) =
                        ready.wait_timeout(count, Duration::from_secs(5)).unwrap();
                    count = guard;
                    if timeout.timed_out() {
                        break;
                    }
                }
                let status = if *count >= 2 {
                    "200 OK"
                } else {
                    "503 Service Unavailable"
                };
                drop(count);
                let body = format!("BACKEND-SAW:\n{}", String::from_utf8_lossy(&head));
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    addr
}

/// A client that negotiated h2 gets HTTP/2 terminated by the sidecar and its
/// request translated to HTTP/1.1 against the backend, then translated back.
#[test]
fn h2_is_terminated_and_translated_to_h1() {
    let pki = Pki::generate();
    let (_running, addr) = run(config(h2_profile(&pki), start_backend()));
    let mut send_request = connect_h2(&pki, addr);

    let (response, _send_stream) = send_request.send_request(get("/"), true).unwrap();
    let response = drive(response).unwrap();

    let (parts, body) = response.into_parts();
    assert_eq!(parts.status, 200);
    assert_eq!(parts.headers.get("x-negotiated-alpn").unwrap(), "h2");
    assert!(parts.headers.get("x-negotiated-version").is_some());

    let text = String::from_utf8_lossy(&read_body(body)).into_owned();
    assert!(
        text.to_ascii_lowercase()
            .contains("x-forwarded-proto: https"),
        "backend saw: {text}"
    );
}

#[test]
fn post_body_reaches_the_backend_and_is_echoed() {
    let pki = Pki::generate();
    let (_running, addr) = run(config(h2_profile(&pki), start_echo_backend()));
    let mut send_request = connect_h2(&pki, addr);

    let request = http::Request::builder()
        .method("POST")
        .uri("https://localhost/echo")
        .body(())
        .unwrap();
    let (response, mut send_stream) = send_request.send_request(request, false).unwrap();
    send_stream
        .send_data(Bytes::from_static(b"hello sidecar"), true)
        .unwrap();

    let response = drive(response).unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(read_body(response.into_body()).as_slice(), b"hello sidecar");
}

#[test]
fn two_streams_share_one_connection() {
    let pki = Pki::generate();
    let (_running, addr) = run(config(h2_profile(&pki), start_gated_backend()));
    let mut send_request = connect_h2(&pki, addr);

    let (first, _) = send_request.send_request(get("/one"), true).unwrap();
    let (second, _) = send_request.send_request(get("/two"), true).unwrap();
    let first = drive(first).unwrap();
    let second = drive(second).unwrap();
    assert_eq!(first.status(), 200);
    assert_eq!(second.status(), 200);

    let first = String::from_utf8_lossy(&read_body(first.into_body())).into_owned();
    let second = String::from_utf8_lossy(&read_body(second.into_body())).into_owned();
    assert!(first.contains("/one"), "backend saw: {first}");
    assert!(second.contains("/two"), "backend saw: {second}");
}

#[test]
fn response_larger_than_one_chunk_arrives_intact() {
    let size = 40 * 1024;
    let pki = Pki::generate();
    let (_running, addr) = run(config(h2_profile(&pki), start_large_backend(size)));
    let mut send_request = connect_h2(&pki, addr);

    let (response, _) = send_request.send_request(get("/large"), true).unwrap();
    let response = drive(response).unwrap();
    assert_eq!(response.status(), 200);

    let expected: Vec<u8> = (0..size).map(|index| b'a' + (index % 26) as u8).collect();
    assert_eq!(read_body(response.into_body()), expected);
}
