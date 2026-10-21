"""Checks for the 7 review items (new behaviour). Runs real code against local fake sites."""
import dataclasses, io, json, logging, os, sys, time
import _paths
for k in list(os.environ):
    if k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS", "NOTIFY_ON_BLOCKED_CHANGE", "DRY_RUN", "REQUEST_TIMEOUT_SECONDS", "CLOUDFLARE_RETRY_GAP_SECONDS"):
        os.environ.pop(k)
os.environ["NO_PROXY"] = "*"; os.environ["STATE_SALT"] = "t"
from monitor.config import load_settings, load_sites_report, warn_about_removed_settings, Site, make_site_id, ConfigError
from monitor.checks import classify as c, uptime
from monitor.logic import evaluate_uptime, apply_delivery
from monitor.state import get_site_state
from monitor.notifiers.email_smtp import build_text, build_html
import cf_server
cf_server.start()
S = load_settings(); BASE = "http://127.0.0.1:8083"
failed = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else ""))
    if not cond: failed.append(label)
def visit(path, base=BASE, settings=S, **kw):
    url = base + path
    s = Site(index=1, name="Client " + path, url=url, site_id=make_site_id("t", url), expected_domain="x", **kw)
    return s, uptime.run_uptime_checks([s], settings, set(), sleep=lambda x: None)[s.site_id]
def logic(s, r, st=None, now=None):
    st = st or {"meta": {}, "sites": {}}; ss = get_site_state(st, s.site_id)
    return evaluate_uptime(s, ss, r, now or time.time(), S), ss, st

print("== Item 2/3: no response or no usable page can never be labelled UP")
HTTPS = "https://127.0.0.1:8443"
s, r = visit("/cf-ok", base=HTTPS, behind_cloudflare=True); al, ss, _ = logic(s, r)
expect("Cloudflare site, cert invalid, no HTTP response -> UNKNOWN, silent", r.status_code is None and al == [] and ss["last_state"] == "UNKNOWN", (ss["last_state"], al))
print("      note:", r.note)
expect("note says no response, certificate invalid, no alert because Cloudflare site", r.note == "no response, certificate invalid, no alert because Cloudflare site", r.note)
s, r = visit("/ok", base=HTTPS); al, ss, _ = logic(s, r)
expect("normal site, cert invalid -> WARNING (email), not UP", ss["last_state"] == "WARNING" and len(al) == 1 and al[0].tag == "tls")
for path, kw, label in (("/plain-503", {"uptime_source": "external"}, "503 external"), ("/plain-403", {}, "403 self"), ("/plain-401", {}, "401"), ("/plain-405", {}, "405"), ("/plain-429", {}, "429")):
    s, r = visit(path, **kw); al, ss, _ = logic(s, r)
    want = ("WARNING", ["WARNING"]) if label == "503 external" else ("UNKNOWN", [])   # P0 3: external sites warn on 5xx
    expect(f"{label}: label {want[0]}, alerts {want[1]}", ss["last_state"] == want[0] and [a.kind for a in al] == want[1] and ss["status"] == "up", (ss["last_state"], al))
print("      note:", r.note)
s, r = visit("/cf-ok"); al, ss, _ = logic(s, r); expect("a clean 200 is the only thing labelled UP", ss["last_state"] == "UP" and r.status_code == 200)
s, r = visit("/plain-403"); al, ss, _ = logic(s, r); expect("history records 'unknown' (null), not 'up'", ss["history"][-1][1] is None, ss["history"])
s, r = visit("/cf-ok"); al, ss, _ = logic(s, r); expect("history records 1 for a clean page", ss["history"][-1][1] == 1)
s, r = visit("/plain-500"); al, ss, _ = logic(s, r); expect("history records 0 for confirmed DOWN", ss["history"][-1][1] == 0)
s, r = visit("/hang", settings=dataclasses.replace(S, read_timeout=1.0), uptime_source="external"); al, ss, _ = logic(s, r)
expect("timeout on an external site: WARNING (P0 3)", ss["last_state"] == "WARNING" and [a.kind for a in al] == ["WARNING"])
s, r = visit("/cf-challenge", behind_cloudflare=True); al, ss, _ = logic(s, r); expect("challenge stays INSPECTION_BLOCKED (not UNKNOWN)", ss["last_state"] == "INSPECTION_BLOCKED")

print("\n== Certificate trust lists disagree (requests rejects, operating system would accept)")
os.environ["SSL_CERT_FILE"] = os.environ["SP"] + "/certs/cert.pem"
s, r = visit("/ok", base=HTTPS); al, ss, _ = logic(s, r)
expect("requests rejects the cert -> TLS_WARN -> WARNING, never DOWN", r.signal == c.TLS_WARN and r.verdict == c.VERDICT_NOT_DOWN and len(al) == 1 and al[0].kind == "WARNING", (r.signal, r.verdict, [a.kind for a in al]))
expect("TLS evidence agrees (cert_invalid, same trust list as requests)", r.probes.tls == "cert_invalid", r.probes.tls)
os.environ.pop("SSL_CERT_FILE")
print("\n== Item 4: connection_refused_is_warning is per site")
dead = "http://127.0.0.1:9"
s1, r1 = visit("/", base=dead); al1, ss1, _ = logic(s1, r1)
s2, r2 = visit("/", base=dead + "/x", connection_refused_is_warning=True); al2, ss2, _ = logic(s2, r2)
expect("same refused connection, flag NOT set -> real DOWN after 3 of 3 CONN_FAIL", r1.verdict == c.VERDICT_DOWN and r1.signal == c.CONN_FAIL and al1[0].kind == "DOWN" and ss1["last_state"] == "DOWN")
expect("same refused connection, flag set on THIS site only -> WARNING", al2[0].kind == "WARNING" and ss2["last_state"] == "WARNING")
sites = [{"name": "A", "url": "https://a.example.com"}, {"name": "SRTC", "url": "https://srtc.example.com", "connection_refused_is_warning": True}, {"name": "B", "url": "https://b.example.com"}]
os.environ["SITES_JSON"] = json.dumps(sites); loaded = load_sites_report(S).sites
expect("config: only the site that sets it has it", [x.connection_refused_is_warning for x in loaded] == [False, True, False])
os.environ.pop("SITES_JSON")
expect("there is no global switch for it in the settings", not hasattr(S, "connection_refused_is_warning"))

print("\n== Item 5: Cloudflare 1xxx split in two families")
for path, code in (("/cf-1020", 1020), ("/cf-1015", 1015), ("/cf-1013", 1013), ("/cf-1999", 1999)):
    s, r = visit(path); al, ss, _ = logic(s, r)
    expect(f"{code}: visitor family -> silent, INSPECTION_BLOCKED, 1 visit", r.signal == c.CF_VISITOR_BLOCK and al == [] and ss["last_state"] == "INSPECTION_BLOCKED" and r.attempts == 1, (r.signal, al))
for path, code in (("/cf-1016", 1016), ("/cf-1001", 1001)):
    s, r = visit(path); al, ss, _ = logic(s, r)
    expect(f"{code}: site family -> confirmed on 3 visits -> ONE WARNING, never DOWN", r.signal == c.CF_CONFIG_ERROR and r.attempts == 3 and r.config_confirmed and r.verdict == c.VERDICT_NOT_DOWN and len(al) == 1 and al[0].kind == "WARNING" and ss["last_state"] == "WARNING" and ss["status"] != "down", (r.attempts, [a.kind for a in al]))
print("      1016 summary:", al[0].summary if al else None)
s, r = visit("/cf-1016"); al, ss, st = logic(s, r)
d = dict(al[0].details); expect("warning carries the code and evidence", d.get("Cloudflare error code") == "1016, 1016, 1016" and "Attempt 3" in d and any(k.startswith("DNS via") for k in d), list(d))
for a in al: apply_delivery(st, a, time.time())
al2, _, _ = logic(s, r, st=st, now=time.time() + 300); expect("not repeated on the next run", al2 == [])
al3, _, _ = logic(s, r, st=st, now=time.time() + 25 * 3600); expect("repeated after 24 hours", len(al3) == 1)
_, okr = visit("/cf-ok"); al4, ss4, _ = logic(s, okr, st=st, now=time.time() + 26 * 3600); expect("clears when the site is fine again", ss4["config_error_active"] is False and ss4["last_state"] == "UP")
s, r = visit("/cf-1016-then-ok"); al, ss, _ = logic(s, r)
expect("1016 once, then fine -> silent (needs all 3 visits)", r.signal == c.OK and al == [] and not r.config_confirmed and r.attempts == 2, (r.signal, r.attempts))
s, r = visit("/cf-1016", behind_cloudflare=True, uptime_source="external"); al, ss, _ = logic(s, r)
expect("external site: 1016 still warns (never DOWN)", len(al) == 1 and al[0].kind == "WARNING" and r.verdict != c.VERDICT_DOWN)
sample = al
text = (build_text(sample) + build_html(sample)).lower()
expect("warning email has none of the banned words", not any(w in text for w in ("unverified", "blocked", "could not check")), [w for w in ("unverified", "blocked", "could not check") if w in text])
print("      family lists: warning =", sorted(c.CF_CONFIG_ERRORS)); 

print("\n== Item 6: removed settings are not silent")
buf = io.StringIO(); h = logging.StreamHandler(buf); logging.getLogger("monitor.config").addHandler(h); logging.getLogger("monitor.config").setLevel(logging.INFO)
os.environ["REQUEST_TIMEOUT_SECONDS"] = "999"; os.environ["CLOUDFLARE_RETRY_GAP_SECONDS"] = "77"; os.environ["RETRY_GAP_SECONDS"] = "15"
warn_about_removed_settings(); out = buf.getvalue()
expect("REQUEST_TIMEOUT_SECONDS named, says ignored, names the replacements", "REQUEST_TIMEOUT_SECONDS" in out and "ignored" in out and "CONNECT_TIMEOUT_SECONDS" in out and "READ_TIMEOUT_SECONDS" in out)
expect("CLOUDFLARE_RETRY_GAP_SECONDS named, says ignored, names the replacement", "CLOUDFLARE_RETRY_GAP_SECONDS" in out and "RETRY_GAP_SECONDS" in out)
expect("the values themselves are never printed", "999" not in out and "77" not in out)
expect("RETRY_GAP_SECONDS below 60 gets a warning", "below 60" in out)
for k in ("REQUEST_TIMEOUT_SECONDS", "CLOUDFLARE_RETRY_GAP_SECONDS", "RETRY_GAP_SECONDS"): os.environ.pop(k)
buf.truncate(0); buf.seek(0); warn_about_removed_settings(); expect("nothing printed when none is set", buf.getvalue() == "")
os.environ["SITES_JSON"] = json.dumps([{"name": "A", "url": "https://a.example.com", "allow_auth": True}])
buf.truncate(0); buf.seek(0); load_sites_report(S); expect("allow_auth in SITES_JSON is reported once too", "allow_auth" in buf.getvalue() and "ignored" in buf.getvalue())
os.environ.pop("SITES_JSON")
print("\nRESULT:", "ALL PASSED" if not failed else f"{len(failed)} FAILED -> {failed}")
sys.exit(1 if failed else 0)
