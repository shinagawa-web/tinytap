# app.py — a plain app that calls the OpenAI API. No proxy, no cert install.
#
# Run it as `.venv/bin/myapp app.py`, where myapp is a copy of the venv python
# (see demo-split.sh). Why not `python3 app.py`?
#   - tinytap's TUI filter matches /proc/pid/comm (TASK_COMM, 15 chars, no
#     args), so the client needs a comm distinct from the server to be
#     isolated with /myapp; plain "python3" collides with the server.
#   - Do NOT invoke via a symlink (e.g. ./myapp): that breaks the venv's
#     site-packages detection and app.py dies with ModuleNotFoundError: httpx,
#     which silently yields zero captured requests.
import socket, ssl, time, httpx
from openai import OpenAI

client = OpenAI(
    api_key="sk-demo-abc123FAKEkeyNOTreal456",     # dummy key — never a real one
    base_url="https://127.0.0.1:8443/v1",          # self-signed local server
    http_client=httpx.Client(verify=False),        # trust the self-signed cert
)

# Warm-up = a TLS handshake with NO HTTP body. tinytap's SSL uprobe only
# captures SSL_write calls made AFTER it attaches, and attach happens ~200ms
# after it first sees this pid. A cold single request would be missed. The
# handshake makes tinytap discover + attach to this pid, but it performs no
# application SSL_write, so it produces NO row. After we sleep past the attach,
# the one real request below is the only captured row (1 execution = 1 row).
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
try:
    _s = _ctx.wrap_socket(socket.create_connection(("127.0.0.1", 8443)),
                          server_hostname="localhost")
    _s.close()
except Exception:
    pass
time.sleep(1.5)   # let the attach complete

client.chat.completions.create(          # the one request tinytap captures
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "what is a uprobe"}],
)
print("done", flush=True)
