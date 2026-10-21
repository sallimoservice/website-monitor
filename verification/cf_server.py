"""Fake websites that behave like Cloudflare (and not). HTTP on 8083, HTTPS with a bad certificate on 8443."""
import http.server, json, os, ssl, threading, time

import _paths
HERE = os.environ["SP"]   # certs and dyn_modes.json live in the work folder
CF = {"server": "cloudflare", "cf-ray": "8a1b2c3d4e5f6a7b-FRA"}
hits = {}
conns = {"n": 0}

NORMAL = b"<html><head><title>Fine</title></head><body>Welcome. Book a ride today.<script src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'></script></body></html>"
NO_TEXT = b"<html><head><title>Fine</title></head><body>Welcome.</body></html>"
CHALLENGE = b"<html><head><title>Just a moment...</title></head><body>Checking your browser before accessing the site. cf-chl-opt</body></html>"
BLOCK_1020 = b"<html><head><title>Attention Required! | Cloudflare</title></head><body><span class='cf-error-code'>1020</span> Access denied. Error code 1020</body></html>"
ERR_521 = b"<html><body>Web server is down. Cloudflare</body></html>"

ROUTES = {
    # path: (status, extra headers, body)
    "/ok": (200, {}, NORMAL),
    "/cf-ok": (200, CF, NORMAL),
    "/cf-ok-notext": (200, CF, NO_TEXT),
    "/cf-challenge": (403, {**CF, "cf-mitigated": "challenge"}, CHALLENGE),
    "/cf-challenge-title200": (200, CF, CHALLENGE),
    "/cf-503": (503, CF, b"<html>Service Unavailable</html>"),
    "/cf-429": (429, CF, b"<html>Too many</html>"),
    "/cf-1020": (403, CF, BLOCK_1020),
    "/cf-521": (521, CF, ERR_521),
    "/cf-522": (522, CF, ERR_521),
    "/cf-1016": (530, CF, b"<html><head><title>Error 1016 Origin DNS error | Cloudflare</title></head><body><span class='cf-error-code'>1016</span> Origin DNS error. Cloudflare</body></html>"),
    "/cf-1001": (409, CF, b"<html><body><span class='cf-error-code'>1001</span> DNS resolution error. Cloudflare</body></html>"),
    "/cf-1015": (429, CF, b"<html><body><span class='cf-error-code'>1015</span> You are being rate limited. Cloudflare</body></html>"),
    "/cf-1013": (403, CF, b"<html><body><span class='cf-error-code'>1013</span> HTTP hostname and TLS SNI hostname mismatch. Cloudflare</body></html>"),
    "/cf-1999": (403, CF, b"<html><body><span class='cf-error-code'>1999</span> Some new code. Cloudflare</body></html>"),
    "/cf-429-mitigated": (429, {**CF, "cf-mitigated": "challenge"}, b"<html><body>Too many requests</body></html>"),
    "/cf-503-maint": (503, CF, b"<html><head><title>Maintenance</title></head><body>Down for maintenance, back in just a moment. Checking your browser is not needed.</body></html>"),
    "/cf-503-attn": (503, CF, b"<html><head><title>Service unavailable</title></head><body>Attention required: the booking system is being updated.</body></html>"),
    "/cf-503-title-jam": (503, CF, b"<html><head><title>Just a moment...</title></head><body>Please wait</body></html>"),
    "/cf-403-attn-title": (403, CF, b"<html><head><title>Attention Required! | Cloudflare</title></head><body>Please complete the security check</body></html>"),
    "/cf-502": (502, CF, b"<html>Bad gateway</html>"),
    "/cf-504": (504, CF, b"<html>Gateway timeout</html>"),
    "/cf-524": (524, CF, ERR_521),
    "/cf-503-origin": (503, CF, b"<html><head><title>Service Unavailable</title></head><body>Service Unavailable<script src='/cdn-cgi/challenge-platform/h/b/scripts/jsd/abc123/main.js'></script></body></html>"),
    "/cf-503-iuam": (503, CF, b"<html><head><title>Just a moment...</title></head><body>Enable JavaScript and cookies to continue<script src='/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1?ray=8a1b'></script></body></html>"),
    "/cf-403-orchestrate": (403, CF, b"<html><head><title>Security check</title></head><body><script src='/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1?ray=8a1b'></script></body></html>"),
    "/cf-403-plain": (403, CF, b"<html><body>Forbidden</body></html>"),
    "/cf-500-origin": (500, CF, b"<html><body>Internal Server Error</body></html>"),
    "/plain-503": (503, {}, b"down"),
    "/plain-403": (403, {}, b"nope"),
    "/plain-404": (404, {}, b"gone"),
    "/plain-410": (410, {}, b"gone"),
    "/plain-401": (401, {}, b"login"),
    "/plain-405": (405, {}, b"no"),
    "/plain-429": (429, {}, b"slow down"),
    "/plain-500": (500, {}, b"boom"),
    "/challenge-no-expected": (403, {**CF, "cf-mitigated": "challenge"}, CHALLENGE),
}

class Site(http.server.BaseHTTPRequestHandler):
    def setup(self):
        conns["n"] += 1
        super().setup()
    def log_message(self, *a): pass
    def do_GET(self):
        raw = self.path
        path = raw.split("?")[0]
        query = dict(q.split("=", 1) for q in raw.split("?", 1)[1].split("&")) if "?" in raw else {}
        hits[raw] = hits.get(raw, 0) + 1
        n = hits[raw]
        if path == "/cf-521-then-ok":                    # fails on the first visit only
            status, extra, body = (521, CF, ERR_521) if n == 1 else (200, CF, NORMAL)
        elif path == "/cf-mixed":                         # 521, 522, 521 ...
            status, extra, body = (521 if n % 2 else 522, CF, ERR_521)
        elif path == "/cf-1016-then-ok":                  # 1016 on the first visit only
            status, extra, body = (530, CF, ROUTES["/cf-1016"][2]) if n == 1 else (200, CF, NORMAL)
        elif path == "/dyn":                                # behaviour switched between runs by dyn_modes.json
            try: modes = json.load(open(os.path.join(HERE, "dyn_modes.json")))
            except Exception: modes = {}
            mode = modes.get(query.get("s", ""), "ok")
            if mode == "drop":
                self.connection.shutdown(2); return
            if mode == "520": status, extra, body = 520, CF, ERR_521
            elif mode == "522": status, extra, body = 522, CF, ERR_521
            elif mode == "slow": time.sleep(4); status, extra, body = 200, CF, NORMAL
            else: status, extra, body = 200, CF, NORMAL
        elif path == "/cf-hang-once":                       # times out on the first visit only
            if n == 1: time.sleep(3)
            status, extra, body = 200, CF, NORMAL
        elif path == "/cf-trouble-mix":                     # 522, then 504, then no answer in time
            if n == 1: status, extra, body = 522, CF, ERR_521
            elif n == 2: status, extra, body = 504, CF, b"<html>Gateway timeout</html>"
            else: time.sleep(3); status, extra, body = 200, CF, NORMAL
        elif path == "/slow22":
            time.sleep(22); status, extra, body = 200, {}, NORMAL
        elif path == "/cf-hang":
            time.sleep(4); status, extra, body = 200, CF, NORMAL
        elif path == "/hang":
            time.sleep(4); status, extra, body = 200, {}, NORMAL
        elif path in ROUTES:
            status, extra, body = ROUTES[path]
        else:
            status, extra, body = 404, {}, b"missing"
        self.send_response(status)
        for k, v in extra.items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        try: self.wfile.write(body)
        except BrokenPipeError: pass

class _Quiet(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):   # a client hanging up mid-answer is part of some tests, not news
        pass


def start():
    if getattr(start, "servers", None):
        return start.servers
    plain = _Quiet(("127.0.0.1", 8083), Site)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    secure = _Quiet(("127.0.0.1", 8443), Site)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(HERE, "certs/cert.pem"), os.path.join(HERE, "certs/key.pem"))
    secure.socket = ctx.wrap_socket(secure.socket, server_side=True)
    threading.Thread(target=secure.serve_forever, daemon=True).start()
    start.servers = (plain, secure)
    return start.servers

if __name__ == "__main__":
    start(); print("fake sites up (8083 http, 8443 https with untrusted cert)", flush=True)
    while True: time.sleep(3600)
