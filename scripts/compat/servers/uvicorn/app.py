import mimetypes
import os

TESTDATA = os.path.join(os.path.dirname(__file__), "../../../../testdata")


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    path = scope["path"].lstrip("/")
    filepath = os.path.join(TESTDATA, path)
    try:
        with open(filepath, "rb") as f:
            body = f.read()
        status = 200
        content_type = mimetypes.guess_type(filepath)[0] or "application/octet-stream"
    except FileNotFoundError:
        body = b"not found"
        status = 404
        content_type = "text/plain"

    headers = [
        [b"content-length", str(len(body)).encode()],
        [b"content-type", content_type.encode()],
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
