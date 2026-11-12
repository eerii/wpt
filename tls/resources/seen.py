import json


def main(request, response):
    response.headers.set(b"content-type", b"application/json")
    response.headers.set(b"access-control-allow-origin", b"*")
    return json.dumps({
        "url": request.url,
        "scheme": request.url_parts.scheme,
        "host": request.url_parts.hostname,
    })
