"""What the monitor sends and how it reads plain answers, against a local server (no Cloudflare unless a route adds it).

Ported from the Stage 1 script: the rules changed in Stage A (3 visits 60 seconds apart, not 4 visits 15 seconds
apart; a 520 is a warning), so the numbers below are today's rules. Sleep is faked so the gaps are recorded, not waited.
"""
import _paths
import dataclasses
import http.server
import json
import os
import sys
import threading
import time

for k in ("RETRY_GAP_SECONDS", "STAGGER_SECONDS", "REQUEST_TIMEOUT_SECONDS", "CLOUDFLARE_RETRY_GAP_SECONDS", "GITHUB_ACTIONS"):
    os.environ.pop(k, None)
os.environ["NO_PROXY"] = "*"
from monitor.checks import classify as c
from monitor.checks.uptime import check_site
from monitor.config import Site, load_settings

CF = {"server": "cloudflare", "cf-ray": "8a1b2c3d4e5f6a7b-FRA"}
hits = {}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path; hits[p] = hits.get(p, 0) + 1; n = hits[p]
        code, body, extra = 200, b"ok", {}
        if p.startswith("/c4"): code = int(p[2:])
        elif p in ("/s500", "/s503"): code = int(p[2:])
        elif p in ("/cf520", "/cf521", "/cf522", "/cf523", "/cf524"): code, extra = int(p[3:]), CF
        elif p == "/cfonce": code, extra = (520 if n == 1 else 200), CF
        elif p == "/mixed": code, extra = (520 if n == 1 else 500), CF
        elif p == "/redir": code = 302; extra = {"Location": "/landed"}
        elif p == "/landed": body = b"landed"
        elif p == "/hang": time.sleep(3)
        elif p == "/headers": body = json.dumps({"method": "GET", **{k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(code)
        for k, v in extra.items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_HEAD(self):   # would expose any accidental HEAD use
        hits["HEAD"] = hits.get("HEAD", 0) + 1; self.send_response(200); self.end_headers()

class _Quiet(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):   # the timeout test hangs up on purpose
        pass
srv = _Quiet(("127.0.0.1", 8082), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

s = load_settings()
failures = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if detail and not cond else ""))
    if not cond: failures.append(label)

expect("defaults: connect 10s, read 30s", (s.connect_timeout, s.read_timeout) == (10, 30), (s.connect_timeout, s.read_timeout))
expect("defaults: 3 visits, 60s gap", (s.retry_attempts, s.retry_gap_seconds) == (3, 60), (s.retry_attempts, s.retry_gap_seconds))
FAST = dataclasses.replace(s, stagger_seconds=0.0, read_timeout=1.0)

def run(path, settings=FAST, base="http://127.0.0.1:8082"):
    site = Site(index=1, name="T", url=base + path, site_id="x", expected_domain="127.0.0.1")
    sleeps = []
    r = check_site(site, settings, sleep=sleeps.append)
    return r, sleeps
def gaps_ok(sleeps, n=2): return len(sleeps) == n and all(55 <= x <= 60 for x in sleeps)

print("\n-- a normal answer is UP, a server that answered is not DOWN, no retries")
r, sl = run("/headers"); expect("2xx = UP, one visit", r.signal == c.OK and r.attempts == 1 and not sl)
r, sl = run("/redir"); expect("a redirect is followed", r.signal == c.OK and r.final_url.endswith("/landed"), r.final_url)
for code in (400, 401, 403, 405, 418, 429, 451):
    r, sl = run(f"/c{code}"); expect(f"{code} = not DOWN, one visit", r.verdict == c.VERDICT_NOT_DOWN and r.attempts == 1 and not sl and r.status_code == code, (r.verdict, r.attempts, sl))

print("\n-- 404, 410 and 5xx on a normal site are DOWN after 3 visits one gap apart")
for path in ("/c404", "/c410", "/s500", "/s503"):
    r, sl = run(path); expect(f"{path} = DOWN after 3 visits", r.verdict == c.VERDICT_DOWN and r.attempts == 3 and gaps_ok(sl), (r.verdict, r.attempts, sl))
r, sl = run("/", base="http://127.0.0.1:9"); expect("connection refused = DOWN after 3 visits", r.verdict == c.VERDICT_DOWN and r.signal == c.CONN_FAIL and r.attempts == 3 and gaps_ok(sl), (r.signal, r.attempts, sl))
r, sl = run("/", base="http://no-such-domain-xyz.invalid"); expect("a domain that does not exist = DOWN (DNS_FAIL)", r.verdict == c.VERDICT_DOWN and r.signal == c.DNS_FAIL, (r.signal, r.verdict))
r, sl = run("/hang"); expect("timeout = DOWN after 3 visits", r.verdict == c.VERDICT_DOWN and r.signal == c.TIMEOUT and r.attempts == 3, (r.signal, r.attempts))

print("\n-- Cloudflare 52x (answered with Cloudflare headers)")
for code in (521, 522, 523, 524):
    r, sl = run(f"/cf{code}"); expect(f"{code} on all 3 visits = DOWN", r.verdict == c.VERDICT_DOWN and r.attempts == 3, (r.verdict, r.attempts))
r, sl = run("/cf520"); expect("520 on all 3 visits = warning, never DOWN", r.verdict != c.VERDICT_DOWN and r.origin_trouble_confirmed and r.attempts == 3, (r.verdict, r.origin_trouble_confirmed))
r, sl = run("/cfonce"); expect("520 then a clean page -> UP, nothing to report", r.signal == c.OK and r.verdict == c.VERDICT_NOT_DOWN and r.attempts == 2 and not r.origin_trouble_confirmed, (r.signal, r.attempts))
r, sl = run("/mixed"); expect("520 then plain 500s -> a mix of trouble, a warning, not DOWN", r.verdict != c.VERDICT_DOWN and r.origin_trouble_confirmed and r.attempts == 3, (r.verdict, r.attempts))

print("\n-- the request itself")
r, _ = run("/headers")
sent = json.loads(r.body)
expect("uses GET and never HEAD", sent["method"] == "GET" and "HEAD" not in hits)
expect("browser User-Agent", "Mozilla/5.0" in sent["user-agent"] and "Chrome/" in sent["user-agent"], sent["user-agent"])
expect("Accept header sent", "text/html" in sent.get("accept", ""))
expect("Accept-Language header sent", sent.get("accept-language", "").startswith("en-US"))
print("\nRESULT:", "ALL PASSED" if not failures else f"{len(failures)} FAILED -> {failures}")
sys.exit(1 if failures else 0)
