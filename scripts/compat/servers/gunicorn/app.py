import os

TESTDATA = os.path.join(os.path.dirname(__file__), "../../../../testdata")

def app(environ, start_response):
    path = environ["PATH_INFO"].lstrip("/")
    filepath = os.path.join(TESTDATA, path)
    try:
        with open(filepath, "rb") as f:
            body = f.read()
        status = "200 OK"
    except FileNotFoundError:
        body = b"not found"
        status = "404 Not Found"
    start_response(status, [("Content-Length", str(len(body)))])
    return [body]
