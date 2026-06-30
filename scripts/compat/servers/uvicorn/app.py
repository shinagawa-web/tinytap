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
    except FileNotFoundError:
        body = b"not found"
        status = 404
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [[b"content-length", str(len(body)).encode()]],
    })
    await send({"type": "http.response.body", "body": body})
