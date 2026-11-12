import json
import socket


def main(request, response):
    response.headers.set(b"content-type", b"application/json")
    port = request.server.config.ports["tls"][0]
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    data = b""
    try:
        while len(data) < 64:
            chunk = sock.recv(64)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    sock.close()
    return json.dumps({
        "is_http": data.startswith(b"HTTP/"),
        "bytes": len(data),
    })
