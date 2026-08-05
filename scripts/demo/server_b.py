#!/usr/bin/env python3
# Config (b): self-signed local HTTPS server that mimics the OpenAI endpoint.
import http.server, ssl, json

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(n)
        resp = json.dumps({"id": "chatcmpl-demo", "object": "chat.completion",
                           "choices": [{"message": {"role": "assistant",
                            "content": "hello from self-signed"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)
    def log_message(self, *a):
        pass

srv = http.server.HTTPServer(("127.0.0.1", 8443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("server.crt", "server.key")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("[server] https://127.0.0.1:8443 up", flush=True)
srv.serve_forever()
