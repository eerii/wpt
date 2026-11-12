mod common;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use common::*;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// A client that negotiated h2 gets HTTP/2 terminated by the sidecar and its
/// request translated to HTTP/1.1 against the backend, then translated back.
#[test]
fn h2_is_terminated_and_translated_to_h1() {
    let pki = Pki::generate();
    let backend = start_backend();
    let mut p = profile(&pki);
    p.alpn = vec!["h2".into()];
    let (_running, addr) = run(config(p, backend));

    let client_config = make_client(&[&rustls::version::TLS13], roots(&pki.ca_der), &[b"h2"], None, None);
    let conn =
        ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap()).unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_nonblocking(true).unwrap();
    let tls = StreamOwned::new(conn, tcp);

    let (mut send_request, connection) = drive(h2::client::handshake(NonBlocking(tls))).unwrap();
    // The connection future must keep being polled for I/O to progress.
    let connection_thread = std::thread::spawn(move || {
        let _ = drive(connection);
    });

    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/")
        .body(())
        .unwrap();
    let (response_future, _send_stream) = send_request.send_request(request, true).unwrap();
    let response = drive(response_future).unwrap();

    let (parts, mut body) = response.into_parts();
    assert_eq!(parts.status, 200);
    assert_eq!(parts.headers.get("x-negotiated-alpn").unwrap(), "h2");
    assert!(parts.headers.get("x-negotiated-version").is_some());

    let mut received = Vec::new();
    while let Some(chunk) = drive(body.data()) {
        received.extend_from_slice(&chunk.unwrap());
    }
    let text = String::from_utf8_lossy(&received);
    assert!(
        text.to_ascii_lowercase().contains("x-forwarded-proto: https"),
        "backend saw: {text}"
    );

    drop(send_request);
    let _ = connection_thread;
}
