import mimetypes
import os

TESTDATA = os.path.join(os.path.dirname(__file__), "../../../../testdata")


def app(environ, start_response):
    path = environ["PATH_INFO"].lstrip("/")
    filepath = os.path.join(TESTDATA, path)
    try:
        with open(filepath, "rb") as f:
            body = f.read()
        status = "200 OK"
        content_type = mimetypes.guess_type(filepath)[0] or "application/octet-stream"
    except FileNotFoundError:
        body = b"not found"
        status = "404 Not Found"
        content_type = "text/plain"
    headers = [
        ("Content-Length", str(len(body))),
        ("Content-Type", content_type),
    ]
    start_response(status, headers)
    return [body]
