import _paths
import dataclasses, glob, hashlib, http.server, json, os, subprocess, sys, threading, time
SP = os.environ["SP"]
for k in list(os.environ):
    if k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS", "STAGGER_SECONDS"): os.environ.pop(k)
os.environ["NO_PROXY"] = "*"; os.environ["STATE_SALT"] = "t"; os.environ["STAGGER_SECONDS"] = "0"
from monitor.config import load_settings, Site, make_site_id
from monitor.checks import classify as c, uptime
from monitor.logic import evaluate_uptime, apply_delivery
from monitor.state import get_site_state
from monitor import dryrun, heartbeat, state as state_mod
from monitor.notifiers import dispatch
S = load_settings(); FAST = dataclasses.replace(S, retry_gap_seconds=0.0, read_timeout=1.0)
import cf_server
cf_server.start()
failed = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else ""))
    if not cond: failed.append(label)
def mk(path, **kw):
    url = "http://127.0.0.1:8083" + path
    return Site(index=1, name=path, url=url, site_id=make_site_id("t", url), expected_domain="x", **kw)
def visit(path, **kw):
    s = mk(path, **kw); return s, uptime.run_uptime_checks([s], FAST, set(), sleep=lambda x: None)[s.site_id]
def logic(s, r, now=None):
    st = {"meta": {}, "sites": {}}; ss = get_site_state(st, s.site_id)
    return evaluate_uptime(s, ss, r, now or time.time(), S), ss

print("== 1. Eight fixtures through the real classifier, the real retry loop and the real alert logic")
rows = [  # label, path, kwargs, expected signal, expected bucket, expected alert kind or None
 ("real challenge, cf-mitigated", "/cf-challenge", dict(behind_cloudflare=True), c.CHALLENGE, "INSPECTION_BLOCKED", None),
 ("503 + cf-ray, no markers",     "/cf-503", dict(behind_cloudflare=True), c.ORIGIN_5XX, "WARNING", "WARNING"),
 ("503, no cf-ray, self site",    "/plain-503", dict(), c.HTTP_ERROR, "DOWN", "DOWN"),
 ("502 + cf-ray",                 "/cf-502", dict(behind_cloudflare=True), c.ORIGIN_5XX, "WARNING", "WARNING"),
 ("504 + cf-ray",                 "/cf-504", dict(behind_cloudflare=True), c.ORIGIN_5XX, "WARNING", "WARNING"),
 ("522 (Cloudflare origin error)","/cf-522", dict(behind_cloudflare=True), c.CF_ORIGIN_ERROR, "DOWN", "DOWN"),
 ("429 + cf-mitigated",           "/cf-429-mitigated", dict(behind_cloudflare=True), c.CHALLENGE, "INSPECTION_BLOCKED", None),
 ("429 + cf-ray only",            "/cf-429", dict(behind_cloudflare=True), c.HTTP_ERROR, "UNKNOWN", None),
]
import urllib.request
def fetch(path):
    class NoRedirect: pass
    try: r = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8083" + path)); code = r.status; h = r.headers; b = r.read()
    except urllib.error.HTTPError as e: code = e.code; h = e.headers; b = e.read()
    hs = [k for k in ("cf-ray", "cf-mitigated", "server") if k in h]
    return code, "+".join(hs) or "none", b.decode()
print(f"{'fixture':32} {'status':6} {'headers':22} {'body marker':26} {'bucket':19} {'alert sent':10} signal/reason")
for label, path, kw, sig, bucket, alert in rows:
    s, r = visit(path, **kw); al, ss = logic(s, r)
    code, hdrs, body = fetch(path)
    marker = r.marker or "none"
    sent = (al[0].kind if al else "none")
    print(f"{label:32} {code:<6} {hdrs:22} {marker:26} {ss['last_state']:19} {sent:10} {r.signal}")
    expect(f"row '{label}' signal {sig}", r.signal == sig, r.signal)
    expect(f"row '{label}' bucket {bucket}", ss["last_state"] == bucket, ss["last_state"])
    expect(f"row '{label}' alert {alert}", (al[0].kind if al else None) == alert, str([a.kind for a in al]))
_, ra = visit("/cf-challenge", behind_cloudflare=True); _, rb = visit("/cf-503", behind_cloudflare=True)
expect("403+cf-mitigated and 503+cf-ray land in DIFFERENT buckets", ra.signal != rb.signal)
expect("ORIGIN_5XX on a behind_cloudflare site is never DOWN", all(visit(p, behind_cloudflare=True)[1].verdict != c.VERDICT_DOWN for p in ("/cf-503", "/cf-502", "/cf-504")))

print("\n== 1b. Body wording must not turn an origin error into a challenge")
for label, path, sig in [
    ("503 maintenance page saying 'back in just a moment' + 'checking your browser'", "/cf-503-maint", c.ORIGIN_5XX),
    ("503 saying 'Attention required' in the body text",                              "/cf-503-attn", c.ORIGIN_5XX),
    ("503 whose TITLE is 'Just a moment...' (real challenge title)",                   "/cf-503-title-jam", c.CHALLENGE),
    ("403 whose TITLE is 'Attention Required! | Cloudflare'",                          "/cf-403-attn-title", c.CHALLENGE),
    ("200 page titled 'Just a moment...'",                                             "/cf-challenge-title200", c.CHALLENGE),
    ("503 origin page carrying only the ordinary challenge-platform script",           "/cf-503-origin", c.ORIGIN_5XX),
    ("503 iuam page with orchestrate/chl_page scripts",                                "/cf-503-iuam", c.CHALLENGE),
]:
    s, r = visit(path, behind_cloudflare=True)
    expect(f"{label} -> {sig}", r.signal == sig, r.signal)
for body, status, hdr, want in [
    ("<html>Service Unavailable. cf-chl-bypass</html>", 503, {"server": "cloudflare"}, c.CHALLENGE),
    ("<html>please wait, checking your browser</html>", 503, {"server": "cloudflare"}, c.ORIGIN_5XX),
]:
    expect(f"classify_response({status}, {body[:40]!r}) -> {want}", c.classify_response(status, hdr, body).signal == want)

print("\n== 2. Timeouts (this tree)")
s, r = visit("/cf-hang", behind_cloudflare=True); al, ss = logic(s, r)
print(f"  behind Cloudflare, every visit times out : signals {[a.signal for a in r.attempt_log]} -> {ss['last_state']}, alert {[a.kind for a in al]}")
expect("behind-Cloudflare timeouts 3/3 -> WARNING, not DOWN", ss["last_state"] == "WARNING" and [a.kind for a in al] == ["WARNING"] and r.verdict != c.VERDICT_DOWN)
s, r = visit("/hang"); al, ss = logic(s, r)
print(f"  self site, every visit times out         : signals {[a.signal for a in r.attempt_log]} -> {ss['last_state']}, alert {[a.kind for a in al]}")
expect("self-site timeouts 3/3 -> DOWN (Stage 1 behaviour)", ss["last_state"] == "DOWN" and [a.kind for a in al] == ["DOWN"])

print("\n== 3. A slow warning that failed to send is retried (it used to go silent after one failed try)")
s = mk("/slow22"); st = {"meta": {}, "sites": {}}; ss = get_site_state(st, s.site_id)
slow = uptime.UptimeResult(signal=c.OK, status_code=200, response_time=25.0)
a1 = evaluate_uptime(s, ss, slow, 1000, S)
a2 = evaluate_uptime(s, ss, slow, 1000 + 28800, S)       # not delivered: must retry
for a in a2: apply_delivery(st, a, 1000 + 28800)
a3 = evaluate_uptime(s, ss, slow, 1000 + 2 * 28800, S)   # delivered: stays quiet
print(f"  run1 alerts {len(a1)}  run2 (run1 undelivered) {len(a2)}  run3 (run2 delivered) {len(a3)}")
expect("slow: 1 / 1 / 0", (len(a1), len(a2), len(a3)) == (1, 1, 0))

print("\n== 4. Dry-run lock (in-process)")
dryrun.arm()
for what, fn in [("dispatch", lambda: dispatch([], [])), ("ping", lambda: heartbeat.ping("http://127.0.0.1:1/x")),
                 ("save_state", lambda: state_mod.save_state(f"{SP}/r6/never.json", {"sites": {}, "meta": {}}))]:
    try: fn(); expect(f"armed lock blocks {what}", False)
    except dryrun.DryRunViolation: expect(f"armed lock blocks {what}", True)
dryrun.disarm()
expect("lock released afterwards (save works)", (state_mod.save_state(f"{SP}/r6/ok.json", {"sites": {}, "meta": {}}) or True))

# ---- end to end through the real command line ------------------------------------------------------
import cf_server, fake_healthchecks, fake_smtp
cf_server.start(); fake_smtp.start(); fake_healthchecks.start()
HC = fake_healthchecks.paths
def mails(): return sorted(glob.glob(f"{SP}/mail_migration/*.eml"))
SMTP_OK = dict(SMTP_HOST="localhost", SMTP_PORT="465", SMTP_USER="alerts@test.com", SMTP_PASSWORD="SuperSecret123", SMTP_FROM="alerts@test.com", EMAIL_TO="me@test.com")
SMTP_DEAD = dict(SMTP_OK, SMTP_PORT="4655")
def cli(args, sites, state, smtp, hc="http://127.0.0.1:8084/hc", salt="realsalt"):
    env = dict(os.environ, SITES_FILE=f"{SP}/{sites}", STATE_PATH=state, STATE_SALT=salt, RETRY_GAP_SECONDS="1", TEXT_RECHECK_GAP_SECONDS="1",
               NO_PROXY="*", no_proxy="*", SSL_CERT_FILE=f"{SP}/certs/cert.pem", HEALTHCHECK_URL=hc, **smtp)
    for k in ("HTTPS_PROXY", "https_proxy", "SMTP_USER", "SMTP_PASSWORD", "EMAIL_TO", "SMTP_HOST") if not smtp else ():
        env.pop(k, None)
    HC.clear(); m0 = len(mails())
    p = _paths.run_monitor(args, env)
    return p.returncode, p.stdout + p.stderr, list(HC), len(mails()) - m0
def prime(name):   # a state file that has seen both sites before, so nothing counts as a fresh start
    path = f"{SP}/r6/{name}.json"
    if os.path.exists(path): os.remove(path)
    return path
def seed(path):
    rc, out, hc, n = cli([], "hc_sites.json", path, SMTP_OK); return rc

print("\n== 5. Alert delivery and the Healthchecks ping, end to end")
p = prime("h_seed"); seed(p)                       # first run: fresh state, alerts held back
j = json.load(open(p)); broken = [v for v in j["sites"].values() if v["status"] == "down"]
rc, out, hc, n = cli([], "hc_sites.json", p, SMTP_DEAD)
print(f"  H1 SMTP unreachable + a DOWN alert pending : exit {rc}, pings {hc}, mails {n}")
expect("H1 send failure -> job fails (exit 1)", rc == 1)
expect("H1 send failure -> Healthchecks gets /fail and NOT a success ping", hc == ["/hc/fail"], str(hc))
expect("H1 output says the alert was not delivered", "could not be delivered" in out)
j = json.load(open(p)); expect("H1 alert stays pending (down_notified_at empty) so the next run retries", all(v["down_notified_at"] is None for v in j["sites"].values() if v["status"] == "down"))
rc, out, hc, n = cli([], "hc_sites.json", p, SMTP_OK)
print(f"  H2 SMTP works again                         : exit {rc}, pings {hc}, mails {n}")
expect("H2 delivered -> exit 0, one success ping, one email", rc == 0 and hc == ["/hc"] and n == 1, f"{rc} {hc} {n}")
rc, out, hc, n = cli([], "hc_sites.json", p, SMTP_OK)
print(f"  H2b next run, same outage (reminder not due): exit {rc}, pings {hc}, mails {n}")
expect("H2b no repeat email", rc == 0 and hc == ["/hc"] and n == 0)
pn = prime("h3"); seed_rc = cli([], "ok_sites.json", pn, SMTP_OK)[0]
rc, out, hc, n = cli([], "ok_sites.json", pn, {})
print(f"  H3 no email channel configured, nothing to say: exit {rc}, pings {hc}")
expect("H3 no channel configured -> job fails and Healthchecks gets /fail", rc == 1 and hc == ["/hc/fail"], f"{rc} {hc}")
rc, out, hc, n = cli([], "ok_sites.json", pn, SMTP_OK)
print(f"  H4 healthy, nothing to send                  : exit {rc}, pings {hc}, mails {n}")
expect("H4 healthy -> exit 0, one success ping", rc == 0 and hc == ["/hc"] and n == 0)
rc, out, hc, n = cli(["--notify-crash"], "ok_sites.json", pn, SMTP_OK)
print(f"  H5 --notify-crash (monitor itself crashed)   : exit {rc}, pings {hc}, mails {n}")
expect("H5 crash step pings /fail and emails", hc == ["/hc/fail"] and n == 1)

print("\n== 6. A run with no state file")
pf = prime("fresh")
rc, out, hc, n = cli([], "hc_sites.json", pf, SMTP_OK)
j = json.load(open(pf))
line = [l for l in out.splitlines() if "STATE WAS MISSING" in l]
print(f"  exit {rc}, mails {n}, pings {hc}\n  log line: {line[0].split(' - ', 1)[-1][:150] if line else None}")
expect("fresh start: zero emails even though a site is broken", n == 0)
expect("fresh start: exit 0 and a success ping (the monitor itself worked)", rc == 0 and hc == ["/hc"])
expect("fresh start: clear log line", bool(line))
expect("fresh start: state records state_rebuilt and alerts_withheld", j["meta"].get("state_rebuilt_at") and j["meta"]["last_run_stats"]["state_rebuilt"] and j["meta"]["last_run_stats"]["alerts_withheld"] >= 1, str(j["meta"]["last_run_stats"]))
rc, out, hc, n = cli([], "hc_sites.json", pf, SMTP_OK)
print(f"  next run on the rebuilt state: exit {rc}, mails {n}")
expect("run after the rebuild raises the real outage (one email)", rc == 0 and n == 1, f"{rc} {n}")
j = json.load(open(pf)); expect("run after the rebuild is not flagged as rebuilt", not j["meta"]["last_run_stats"]["state_rebuilt"])

print("\n== 7. Dry run end to end (old-format state, real salt)")
old = f"{SP}/mig/state_old.json"; work = f"{SP}/r6/dry_state.json"
json.dump(_paths.age_state(json.load(open(old)), 600), open(work, "w")); before = hashlib.sha256(open(work, "rb").read()).hexdigest()
caches = len(glob.glob(f"{SP}/r6/*"))
rc, out, hc, n = cli(["--dry-run"], "sites17.json", work, SMTP_OK)
after = hashlib.sha256(open(work, "rb").read()).hexdigest()
open(f"{SP}/r6/dry_run_output.txt", "w").write(out)
expect("dry run exit 0", rc == 0, str(rc))
expect("dry run: zero emails", n == 0)
expect("dry run: zero Healthchecks pings", hc == [], str(hc))
expect("dry run: state file byte-for-byte unchanged (zero writes)", before == after)
expect("dry run: no stray temp state files", not glob.glob(f"{SP}/r6/.state-*"))
v = json.load(open(old))
expect("old file is format version 1 (so this is the migration case)", v.get("version") in (None, 1), str(v.get("version")))
for needle, label in [("STATE CHECK", "state check section"), ("format version 1", "old format read"), ("17 of 17 configured sites have saved state", "all 17 had saved state"),
                      ("History kept:", "history preserved line"), ("REQS", "REQS column"), ("CLASSIFICATION (every site", "classification list"),
                      ("WHO SHARES A SERVER", "resolved-IP grouping"), ("WOULD ALERT ON A REAL RUN", "would-alert list"), ("RUN SUMMARY", "run summary"),
                      ("Emails sent 0, Healthchecks pings 0, state writes 0", "zero-send statement"), ("17 sites, 19 page visits", "page visit total")]:
    expect(f"dry run output has: {label}", needle in out, needle)
expect("dry run did NOT start fresh", "STATE WAS MISSING" not in out and "NO SAVED STATE FOUND" not in out)
cls = [l for l in out.splitlines() if l.startswith("  Limo ") and ("UP" in l or "DOWN" in l or "WARNING" in l or "SLOW" in l or "UNKNOWN" in l or "INSPECTION" in l)]
print(f"  classification lines found: {len(cls)}")
expect("17 classification lines, one per site", len(cls) == 17, str(len(cls)))
gs = prime("group_state")
rc, out3, hc, n = cli(["--dry-run"], "group_sites.json", gs, SMTP_OK)
grp = [l for l in out3.splitlines() if "share one address" in l]
print("  grouping demo:", grp)
expect("resolved-IP grouping prints the shared sites and the Server header", len(grp) == 1 and "Server header: BaseHTTP" in grp[0] and "Limo" not in grp[0] and "Shared A, Shared B, Shared C" in grp[0], str(grp))
nf = prime("gone_state")
rc, out2, hc, n = cli(["--dry-run"], "hc_sites.json", nf, SMTP_OK)
expect("dry run with no state file: says so, creates no file", "NO SAVED STATE FOUND" in out2 and not os.path.exists(nf), str(os.path.exists(nf)))
expect("dry run with no state file: no email, no ping", n == 0 and hc == [])

print(f"\n{len(failed)} failed" if failed else "\nALL PASSED")
sys.exit(1 if failed else 0)
