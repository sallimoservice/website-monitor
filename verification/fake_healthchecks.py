"""A fake Healthchecks on localhost:8084. Every request path is recorded in `paths`."""

import http.server
import threading

paths = []


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        paths.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    do_POST = do_GET


def start(port=8084):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
