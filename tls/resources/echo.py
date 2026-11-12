import json


def main(request, response):
    response.headers.set(b"content-type", b"application/json")
    response.headers.set(b"access-control-allow-origin", b"*")
    response.headers.set(b"timing-allow-origin", b"*")
    response.headers.set(
        b"access-control-expose-headers",
        b"x-negotiated-version, x-negotiated-cipher, x-negotiated-alpn",
    )
    headers = {key.decode("latin-1"): request.headers[key].decode("latin-1")
               for key in request.headers}
    return json.dumps(headers)
