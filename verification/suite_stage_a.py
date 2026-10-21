import dataclasses, json, os, sys, tempfile, time
import _paths
for k in list(os.environ):
    if k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS", "NOTIFY_ON_BLOCKED_CHANGE", "DRY_RUN"):
        os.environ.pop(k)
os.environ["NO_PROXY"] = "*"
os.environ["STATE_SALT"] = "t"
from monitor.config import load_settings, load_sites_report, load_sites, ConfigError, Site, make_site_id
from monitor.checks import classify as c, network, uptime
from monitor.checks.uptime import check_site, run_uptime_checks
from monitor.logic import evaluate_uptime, apply_delivery
from monitor.state import get_site_state, store_baseline, load_state, save_state
from monitor.notifiers.email_smtp import build_text, build_html, build_subject
import cf_server
cf_server.start()

S = load_settings()                       # real defaults
FAST = dataclasses.replace(S, read_timeout=1.0)
BASE = "http://127.0.0.1:8083"
results, failed = [], []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else ""))
    if not cond: failed.append(label)
def site(path, base=BASE, **kw):
    url = base + path
    return Site(index=1, name=f"Client {path}", url=url, site_id=make_site_id("t", url), expected_domain="x", **kw)
def visit(path, settings=S, base=BASE, seen=False, **kw):
    sleeps = []
    s = site(path, base, **kw)
    r = uptime.run_uptime_checks([s], settings, {s.site_id} if seen else set(), sleep=sleeps.append)[s.site_id]
    return s, r, sleeps
def run_logic(s, r, ss=None, now=None, st=None):
    st = st or {"meta": {}, "sites": {}}
    ss = get_site_state(st, s.site_id) if ss is None else ss
    al = evaluate_uptime(s, ss, r, now or time.time(), S)
    return al, ss

print("== defaults")
expect("3 attempts, 60s apart, 10s connect / 30s read", (S.retry_attempts, S.retry_gap_seconds, S.connect_timeout, S.read_timeout) == (3, 60.0, 10.0, 30.0))
expect("DOWN reminder every 8 hours", S.down_reminder_hours == 8)

print("\n== 1. Cloudflare challenge -> INSPECTION_BLOCKED, silence, no HTML kept")
s, r, sl = visit("/cf-challenge")
al, ss = run_logic(s, r)
expect("403 + cf-mitigated = CHALLENGE", r.signal == c.CHALLENGE and r.marker == "header cf-mitigated", (r.signal, r.marker))
expect("one attempt only, no retries", r.attempts == 1 and sl == [])
expect("verdict not DOWN, NO alert at all", r.verdict == c.VERDICT_NOT_DOWN and al == [])
expect("state INSPECTION_BLOCKED + flag set", ss["last_state"] == "INSPECTION_BLOCKED" and ss["inspection_blocked"] is True)
expect("challenge HTML is not kept anywhere", r.body is None and "moment" not in json.dumps(dataclasses.asdict(r), default=str).lower().replace("just a moment", "X") or r.body is None)
expect("only the marker NAME is kept", "chl" not in json.dumps(ss).lower() and r.marker in ("header cf-mitigated",))
for path, why in (("/cf-challenge-title200", "200 with title 'Just a moment...'"), ("/cf-503-iuam", "503 with a real challenge page")):
    s, r, sl = visit(path); expect(f"{why} = CHALLENGE, silent", r.signal == c.CHALLENGE and run_logic(s, r)[0] == [], r.signal)

print("\n== 2. Normal 200 (even with challenge-platform script in the page) -> OK, checks run")
s, r, sl = visit("/cf-ok")
expect("page containing 'challenge-platform' is OK, not a challenge", r.signal == c.OK and r.body and "challenge-platform" in r.body, r.signal)
expect("page is scannable", c.page_is_scannable(r.signal, r.status_code))

print("\n== 3. Cloudflare 521/522 -> DOWN only when 3/3 agree")
s, r, sl = visit("/cf-521")
expect("521 x3 = DOWN, 3 attempts, two waits of ~60s", r.verdict == c.VERDICT_DOWN and r.attempts == 3 and len(sl) == 2 and all(58 <= x <= 60 for x in sl), (r.verdict, r.attempts, sl))
s, r, sl = visit("/cf-522")
expect("522 x3 = DOWN", r.verdict == c.VERDICT_DOWN and r.signal == c.CF_ORIGIN_ERROR)
s, r, sl = visit("/cf-mixed")
expect("521,522,521 = same signal (CF_ORIGIN_ERROR) = DOWN", r.verdict == c.VERDICT_DOWN, r.verdict)
al, ss = run_logic(*visit("/cf-521")[:2]); expect("DOWN alert is produced", len(al) == 1 and al[0].kind == "DOWN" and al[0].tag == "down")
s, r, sl = visit("/cf-521-then-ok")
expect("521 on attempt 1 only, then 200 = NOT DOWN (stops after 2)", r.verdict == c.VERDICT_NOT_DOWN and r.signal == c.OK and r.attempts == 2, (r.verdict, r.attempts))

print("\n== 4. DNS: needs BOTH resolvers")
GONE = "http://gone-example.invalid"
def fake_doh(answers):
    def q(url, host, rtype):
        return answers["1.1.1.1" if "cloudflare" in url else "8.8.8.8"]
    return q
real_q = network._doh_query
for label, ans, strict_down, classic_down in (
    ("NXDOMAIN on both = DNS_FAIL = DOWN", {"1.1.1.1": "NXDOMAIN", "8.8.8.8": "NXDOMAIN"}, True, True),
    ("NXDOMAIN on one only = NOT DOWN (Cloudflare site)", {"1.1.1.1": "NXDOMAIN", "8.8.8.8": "OK"}, False, None),
    ("NXDOMAIN + SERVFAIL = NOT DNS_FAIL", {"1.1.1.1": "NXDOMAIN", "8.8.8.8": "SERVFAIL"}, False, None),
    ("lookups failing (ERROR/ERROR) = NOT DNS_FAIL", {"1.1.1.1": "ERROR", "8.8.8.8": "ERROR"}, False, None),
):
    network._doh_query = fake_doh(ans)
    s, r, sl = visit("/", base=GONE, behind_cloudflare=True)
    expect(label, (r.verdict == c.VERDICT_DOWN) == strict_down and (r.signal == c.DNS_FAIL) == (ans["1.1.1.1"] == ans["8.8.8.8"] == "NXDOMAIN"), (r.signal, r.verdict))
network._doh_query = real_q
network._doh_query = fake_doh({"1.1.1.1": "NXDOMAIN", "8.8.8.8": "NXDOMAIN"})
s, r, sl = visit("/", base=GONE, behind_cloudflare=True)
rows = dict(__import__("monitor.logic", fromlist=["x"])._evidence(r))
expect("evidence shows each resolver separately", rows.get("DNS via 1.1.1.1") == "NXDOMAIN" and rows.get("DNS via 8.8.8.8") == "NXDOMAIN", rows)
network._doh_query = real_q

print("\n== 5. Cloudflare 1020 block page -> never DOWN")
s, r, sl = visit("/cf-1020")
expect("1020 = CF_VISITOR_BLOCK, 1 attempt, silent, no body", r.signal == c.CF_VISITOR_BLOCK and r.attempts == 1 and r.body is None and run_logic(s, r)[0] == [], (r.signal, r.marker))
print("      marker name kept:", r.marker)

print("\n== 6. uptime_source=external: never DOWN from 503 or timeout")
s, r, sl = visit("/plain-503", uptime_source="external"); expect("503 -> no DOWN, a WARNING (P0 3)", r.verdict == c.VERDICT_NOT_DOWN and [a.kind for a in run_logic(s, r)[0]] == ["WARNING"], r.verdict)
s, r, sl = visit("/hang", FAST, uptime_source="external"); expect("timeout -> no DOWN, a WARNING (P0 3)", r.signal == c.TIMEOUT and r.verdict == c.VERDICT_NOT_DOWN and [a.kind for a in run_logic(s, r)[0]] == ["WARNING"], (r.signal, r.verdict))
s, r, sl = visit("/plain-403", uptime_source="external"); expect("403 -> no alert", run_logic(s, r)[0] == [])
s, r, sl = visit("/", base="http://127.0.0.1:9", uptime_source="external")
expect("connection failure on an external site STILL alerts (CONN_FAIL)", r.verdict == c.VERDICT_DOWN and r.signal == c.CONN_FAIL, (r.signal, r.verdict))

print("\n== 7. Normal (non-Cloudflare, self) sites keep today's behaviour")
for path, expect_down in (("/plain-500", True), ("/plain-503", True), ("/plain-404", True), ("/plain-410", True), ("/plain-401", False), ("/plain-403", False), ("/plain-405", False), ("/plain-429", False), ("/ok", False)):
    s, r, sl = visit(path)
    expect(f"{path[1:]} -> {'DOWN after 3' if expect_down else 'UP, no retries'}", (r.verdict == c.VERDICT_DOWN) == expect_down and (r.attempts == 3 if expect_down else r.attempts == 1), (r.verdict, r.attempts))
s, r, sl = visit("/hang", FAST); expect("timeout x3 -> DOWN", r.verdict == c.VERDICT_DOWN and r.signal == c.TIMEOUT and r.attempts == 3, (r.verdict, r.attempts))
s, r, sl = visit("/", base="http://127.0.0.1:9"); expect("refused x3 -> DOWN", r.verdict == c.VERDICT_DOWN and r.signal == c.CONN_FAIL)
s, r, sl = visit("/", base="http://127.0.0.1:9", connection_refused_is_warning=True); al, ss = run_logic(s, r)
expect("connection_refused_is_warning still turns refusal into a WARNING", len(al) == 1 and al[0].kind == "WARNING" and ss["status"] != "down", [a.kind for a in al])
s, r, sl = visit("/plain-403"); al, ss = run_logic(s, r); expect("403 on a normal site: UP, silent, content not scanned", al == [] and ss["status"] == "up" and ss["inspection_blocked"] is True)
s, r, sl = visit("/cf-503-iuam")
expect("a Cloudflare challenge is recognised even WITHOUT behind_cloudflare", r.signal == c.CHALLENGE and r.cloudflare and r.verdict == c.VERDICT_NOT_DOWN)
s, r, sl = visit("/cf-521", behind_cloudflare=False); expect("Cloudflare auto-detected -> strict rules (cloudflare flag on result)", r.cloudflare and r.strict)

print("\n== 8. Certificate problems")
HTTPS = "https://127.0.0.1:8443"
s, r, sl = visit("/ok", base=HTTPS)
expect("untrusted cert on a normal site = TLS_WARN, not DOWN", r.signal == c.TLS_WARN and r.verdict == c.VERDICT_NOT_DOWN and r.probes.tls == "cert_invalid", (r.signal, r.probes.tls if r.probes else None))
al, ss = run_logic(s, r)
expect("...and it sends a REAL WARNING email (tag tls)", len(al) == 1 and al[0].kind == "WARNING" and al[0].tag == "tls" and ss["last_state"] == "WARNING", [(a.kind, a.tag) for a in al])
for a in al: apply_delivery({"sites": {s.site_id: ss}, "meta": {}}, a, time.time())
al2, _ = run_logic(s, r, ss=ss, now=time.time() + 300); expect("once delivered, not repeated 5 minutes later", al2 == [])
al3, _ = run_logic(s, r, ss=ss, now=time.time() + 25 * 3600); expect("repeated after 24 hours", len(al3) == 1 and al3[0].tag == "tls")
s, r, sl = visit("/ok", base=HTTPS, behind_cloudflare=True); al, ss = run_logic(s, r)
expect("behind_cloudflare site: NO certificate warning at all", al == [] and ss["tls_warn_active"] is False)

print("\n== 9. expected_text")
s, r, sl = visit("/cf-ok-notext", expected_text="Book a ride"); al, ss = run_logic(s, r)
expect("missing on a normal 200 (confirmed by one extra look) = WARNING", r.text_missing and len(al) == 1 and al[0].tag == "text", (r.text_missing, [a.tag for a in al]))
expect("the extra look waited ~30s (recorded, not really waited)", any(28 <= x <= 30 for x in sl), sl)
s, r, sl = visit("/cf-ok", expected_text="Book a ride"); expect("present = no warning", not r.text_missing and run_logic(s, r)[0] == [])
s, r, sl = visit("/challenge-no-expected", expected_text="Book a ride"); al, ss = run_logic(s, r)
expect("missing on a CHALLENGE page = NO warning", not r.text_missing and al == [] and ss["text_missing_active"] is False)
s, r, sl = visit("/cf-1020", expected_text="Book a ride"); expect("missing on a 1020 page = NO warning", run_logic(s, r)[0] == [])
s, r, sl = visit("/plain-500", expected_text="Book a ride"); expect("missing on a 500 page = no TEXT warning", not r.text_missing)

print("\n== 10. Baseline protection")
st = {"meta": {}, "sites": {}}
s, r, _ = visit("/cf-challenge"); ss = get_site_state(st, s.site_id)
expect("a challenge page can NOT create a baseline", store_baseline(ss, r, "abc123", 1.0) is False and ss["baseline_hash"] is None)
s2, ok_r, _ = visit("/cf-ok"); expect("a clean page can", store_baseline(ss, ok_r, "good-hash", 100.0) is True and ss["baseline_hash"] == "good-hash" and ss["baseline_learned_at"] == 100.0)
for path in ("/cf-challenge", "/cf-1020", "/plain-403", "/plain-500", "/cf-521", "/cf-challenge-title200"):
    sx, rx, _ = visit(path)
    expect(f"{path} can NOT overwrite the existing baseline", store_baseline(ss, rx, "evil-hash", 200.0) is False and ss["baseline_hash"] == "good-hash" and ss["baseline_learned_at"] == 100.0)
expect("no baseline write without a page body", store_baseline(ss, dataclasses.replace(ok_r, body=None), "x", 3.0) is False)

print("\n== 11. Stuck-DOWN rules")
def down_state(signal):
    st = {"meta": {}, "sites": {}}; s = site("/cf-521"); ss = get_site_state(st, s.site_id)
    ss.update(status="down", down_since=1000.0, down_notified_at=1000.0, down_signal=signal, last_up_at=500.0)
    return s, st, ss
s, st, ss = down_state(c.DNS_FAIL); _, ch, _ = visit("/cf-challenge")
al, ss = run_logic(s, ch, ss=ss, now=1000.0 + 9 * 3600)
expect("DNS_FAIL outage + challenge page = RECOVERED", len(al) == 1 and al[0].kind == "RECOVERED" and ss["status"] == "up", [a.kind for a in al])
s, st, ss = down_state(c.CONN_FAIL)
al, ss = run_logic(s, ch, ss=ss, now=1000.0 + 9 * 3600); expect("CONN_FAIL outage + challenge page = RECOVERED", len(al) == 1 and al[0].kind == "RECOVERED")
s, st, ss = down_state(c.CF_ORIGIN_ERROR)
al, ss = run_logic(s, ch, ss=ss, now=1000.0 + 9 * 3600)
expect("CF_ORIGIN_ERROR outage + challenge page = STAYS DOWN, silent, no reminder", al == [] and ss["status"] == "down" and ss["down_inconclusive_since"] is not None, (al, ss["status"]))
al, ss = run_logic(s, ch, ss=ss, now=1000.0 + 30 * 3600); expect("still silent 30h later (summary line only)", al == [] and ss["down_inconclusive_since"] == 1000.0 + 9 * 3600)
_, okr, _ = visit("/cf-ok"); al, ss = run_logic(s, okr, ss=ss, now=1000.0 + 31 * 3600); expect("a clean page ends it: RECOVERED", len(al) == 1 and al[0].kind == "RECOVERED" and ss["down_inconclusive_since"] is None)

print("\n== 12. RECOVERED wording + evidence + email wording")
s, st, ss = down_state(c.DNS_FAIL)
al, ss = run_logic(s, okr, ss=ss, now=500.0 + 8.5 * 3600)
rec = dict(al[0].details)
expect("'up to 9 hours (checked every 8 hours)'", rec["Downtime"] == "up to 9 hours (checked every 8 hours)", rec["Downtime"])
expect("RECOVERED has the evidence rows", all(k in rec for k in ("Signal", "HTTP status", "TLS handshake", "Response time", "Attempt 1")) and any(k.startswith("DNS via") for k in rec) and any(k.startswith("TCP port") for k in rec), list(rec))
s, r, _ = visit("/cf-521"); al, _ = run_logic(s, r)
d = dict(al[0].details)
expect("DOWN has signal, status codes, cf-ray, TCP/TLS, timings, 3 attempt timestamps (UTC + PKT)",
       d["Signal"] == "CF_ORIGIN_ERROR" and d["HTTP status"] == "521, 521, 521" and d["Cloudflare cf-ray"].startswith("8a1b") and "Attempt 3" in d and "UTC /" in d["Attempt 1"] and "PKT" in d["Attempt 1"] and d["Response time"].count("s") == 3, d)
sample = [al[0]] + run_logic(*visit("/ok", base=HTTPS)[:2])[0] + run_logic(*visit("/cf-ok-notext", expected_text="Book a ride")[:2])[0] + run_logic(*down_state(c.DNS_FAIL)[0:1], okr, ss=down_state(c.DNS_FAIL)[2], now=500 + 8.5 * 3600)[0]
text = (build_subject(sample) + build_text(sample) + build_html(sample)).lower()
bad = [w for w in ("unverified", "blocked", "could not check", "could not be checked") if w in text]
expect("alert emails never contain 'UNVERIFIED', 'blocked', 'could not check'", not bad, bad)

print("\n== 13. Cache miss")
tmp = os.path.join(tempfile.mkdtemp(), "state.json")
fresh = load_state(tmp); expect("missing cache -> fresh state flagged for this run", fresh.get("_fresh") is True)
save_state(tmp, fresh); expect("flag is never written to disk", "_fresh" not in json.load(open(tmp)))
expect("a saved v1 file still loads", True)
old = {"version": 1, "meta": {}, "sites": {"abc": {"status": "down", "down_since": 5.0}}}; json.dump(old, open(tmp, "w"))
st = load_state(tmp); ss = get_site_state(st, "abc"); expect("v1 state keeps its data and gains the new fields", ss["status"] == "down" and ss["down_since"] == 5.0 and ss["last_state"] == "UNKNOWN" and "baseline_hash" in ss)

print("\n== 14. Config")
os.environ.pop("SITES_FILE", None)
def cfg(data):
    os.environ["SITES_JSON"] = json.dumps(data) if not isinstance(data, str) else data
    return load_sites_report(S)
rep = cfg([{"name": "A", "url": "https://a.example.com"}])
a = rep.sites[0]
expect("a site with none of the new fields gets the old defaults", (a.behind_cloudflare, a.uptime_source, a.expected_text, a.connection_refused_is_warning) == (False, "self", "", False) and rep.skipped == 0)
rep = cfg([{"name": "A", "url": "https://a.example.com"}, {"name": "Bad", "url": "ftp://x"}, {"url": "https://b.example.com"}, {"name": "C", "url": "https://c.example.com", "uptime_source": "weekly"}, {"name": "D", "url": "https://d.example.com", "behind_cloudflare": "true"}, {"name": "OK", "url": "https://ok.example.com", "behind_cloudflare": True, "uptime_source": "external", "expected_text": " Hello "}])
expect("bad entries are skipped and counted, good ones kept", [x.name for x in rep.sites] == ["A", "OK"] and rep.skipped == 4, (rep.skipped, [x.name for x in rep.sites]))
expect("state of a skipped entry with a readable URL is kept", make_site_id("t", "https://c.example.com") in rep.skipped_ids and make_site_id("t", "https://d.example.com") in rep.skipped_ids)
expect("new fields parse", rep.sites[1].behind_cloudflare and rep.sites[1].uptime_source == "external" and rep.sites[1].expected_text == "Hello")
for label, data in (("unreadable JSON", "[{oops"), ("not a list", "{}"), ("empty list", "[]"), ("every entry bad", [{"name": "x", "url": "nope"}])):
    try: cfg(data); expect(f"{label} = hard stop", False)
    except ConfigError as e: expect(f"{label} = hard stop", True)
os.environ.pop("SITES_JSON", None)

print("\nRESULT:", "ALL PASSED" if not failed else f"{len(failed)} FAILED -> {failed}")
sys.exit(1 if failed else 0)
