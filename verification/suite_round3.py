import dataclasses, io, json, logging, os, sys, tempfile, time
import _paths
for k in list(os.environ):
    if k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS", "REQUEST_TIMEOUT_SECONDS", "CLOUDFLARE_RETRY_GAP_SECONDS", "NOTIFY_ON_BLOCKED_CHANGE", "DRY_RUN", "SMTP_USER", "SMTP_PASSWORD", "EMAIL_TO"):
        os.environ.pop(k)
os.environ["NO_PROXY"] = "*"; os.environ["STATE_SALT"] = "t"
from monitor.config import load_settings, load_sites_report, warn_about_removed_settings, Site, make_site_id
from monitor.checks import classify as c, uptime, network
from monitor.logic import evaluate_uptime, _evidence
from monitor.state import get_site_state
from monitor import main as M
from monitor.notifiers.email_smtp import build_text
import cf_server; cf_server.start()
S = load_settings(); BASE = "http://127.0.0.1:8083"
failed = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else "")); 
    if not cond: failed.append(label)
def mk(path, base=BASE, **kw):
    url = base + path
    return Site(index=1, name="Client " + path, url=url, site_id=make_site_id("t", url), expected_domain="x", **kw)
def visit(path, base=BASE, settings=S, **kw):
    s = mk(path, base, **kw); return s, uptime.run_uptime_checks([s], settings, set(), sleep=lambda x: None)[s.site_id]
def logic(s, r, st=None, now=None):
    st = st or {"meta": {}, "sites": {}}; ss = get_site_state(st, s.site_id)
    return evaluate_uptime(s, ss, r, now or time.time(), S), ss, st

print("== Item 1: read timeout 30s, per-site override, slow is never DOWN")
expect("defaults: connect 10s, read 30s", (S.connect_timeout, S.read_timeout) == (10.0, 30.0), (S.connect_timeout, S.read_timeout))
t0 = time.time(); s, r = visit("/slow22")
expect("a page that takes 22s (Site 03 territory) is answered, not a timeout", r.signal == c.OK and r.status_code == 200 and r.verdict == c.VERDICT_NOT_DOWN and r.attempts == 1, (r.signal, r.attempts))
al, ss, _ = logic(mk("/slow22", slow_threshold_seconds=8.0), r)
expect("...and it is SLOW with a WARNING, never DOWN", ss["last_state"] == "SLOW" and ss["status"] != "down" and len(al) == 1 and al[0].kind == "WARNING" and al[0].tag == "slow", (ss["last_state"], [a.tag for a in al]))
st = {"meta": {}, "sites": {}}; site = mk("/hang", slow_threshold_seconds=1.0)
states = []
for i in range(3):                              # three slow runs in a row (your scenario)
    r = uptime.run_uptime_checks([site], S, set(), sleep=lambda x: None)[site.site_id]
    al, ss, st = logic(site, r, st=st, now=time.time() + i * 28800); states.append(ss["last_state"])
expect("three slow runs in a row: SLOW each time, never DOWN, no DOWN email", states == ["SLOW"] * 3 and ss["status"] != "down", states)
s, r = visit("/hang", settings=dataclasses.replace(S, read_timeout=1.0)); expect("(control) with a 1s timeout the same page IS a timeout", r.signal == c.TIMEOUT)
s, r = visit("/hang", read_timeout_seconds=1); expect("per-site read_timeout_seconds=1 beats the 30s default -> TIMEOUT", r.signal == c.TIMEOUT and "within 1 seconds" in r.error, (r.signal, r.error))
s, r = visit("/hang", settings=dataclasses.replace(S, read_timeout=1.0), read_timeout_seconds=8); expect("per-site read_timeout_seconds=8 beats a 1s default -> answered", r.signal == c.OK, r.signal)
os.environ["SITES_JSON"] = json.dumps([{"name": "A", "url": "https://a.example.com", "read_timeout_seconds": 45}, {"name": "B", "url": "https://b.example.com"}])
l = load_sites_report(S).sites; expect("config: A gets 45, B uses the default (None)", [x.read_timeout_seconds for x in l] == [45.0, None], [x.read_timeout_seconds for x in l])
for bad in (0, -5, 301, "30", True, [1]):
    os.environ["SITES_JSON"] = json.dumps([{"name": "OK", "url": "https://ok.example.com"}, {"name": "Bad", "url": "https://bad.example.com", "read_timeout_seconds": bad}])
    rep = load_sites_report(S); expect(f"read_timeout_seconds={bad!r} is rejected: that entry is skipped, the other site runs", rep.skipped == 1 and [x.name for x in rep.sites] == ["OK"], rep.skipped)
os.environ.pop("SITES_JSON")

print("\n== Item 3: DNS wording")
probes = network.Probes(dns={"1.1.1.1": "ERROR", "8.8.8.8": "SERVFAIL"}, tcp="ok", tls="n/a", port=80)
r = uptime.UptimeResult(signal=c.CF_ORIGIN_ERROR, status_code=521, started_at=time.time(), probes=probes, attempts=3)
rows = dict(_evidence(r))
expect("a failed lookup reads 'not checked (lookup failed)', never ERROR", rows["DNS via 1.1.1.1"] == "not checked (lookup failed)", rows["DNS via 1.1.1.1"])
expect("SERVFAIL is shown as a resolver answer, not as 'not checked'", rows["DNS via 8.8.8.8"].startswith("SERVFAIL") and "resolver" in rows["DNS via 8.8.8.8"])
expect("a raw IP address says 'not needed'", network.dns_words("n/a") == "not needed (address given directly)")
expect("real answers are untouched", network.dns_words("OK") == "OK" and network.dns_words("NXDOMAIN") == "NXDOMAIN")
site = mk("/cf-521", behind_cloudflare=True)
network._doh_query = lambda url, host, rtype: "ERROR"       # as if the resolvers cannot be reached
fake_host = Site(index=1, name="X", url="http://localhost:8083/cf-521", site_id="z" * 16, expected_domain="x", behind_cloudflare=True)
res = uptime.run_uptime_checks([fake_host], S, set(), sleep=lambda x: None)[fake_host.site_id]
al = evaluate_uptime(fake_host, {**get_site_state({"sites": {}}, "z"*16)}, res, time.time(), S)
body = build_text(al).splitlines() if al else []
dns_lines = [x for x in body if x.startswith("DNS via")]
expect("in a real DOWN email both DNS lines say 'not checked (lookup failed)'", len(dns_lines) == 2 and all("not checked (lookup failed)" in x and "ERROR" not in x for x in dns_lines), dns_lines)
print("      ", dns_lines)

print("\n== Item 3: DNS checking degraded detection")
def run_with(paths_bad, paths_good, cf_paths=()):
    sites = [mk(p, base="http://localhost:8083") for p in paths_bad + paths_good]
    bad = set(paths_bad)
    real_probes = uptime.run_probes
    def fake_probes(url, timeout):
        dns = {"1.1.1.1": "ERROR", "8.8.8.8": "ERROR"} if any(url.endswith(b) for b in bad) else {"1.1.1.1": "OK", "8.8.8.8": "OK"}
        pr = real_probes("http://127.0.0.1:8083/ok", timeout); pr.dns = dns; return pr
    uptime.run_probes = fake_probes
    tmp = os.path.join(tempfile.mkdtemp(), "s.json")
    st = dataclasses.replace(S, retry_gap_seconds=0.0, state_path=tmp, text_recheck_gap_seconds=0.0)
    buf = io.StringIO(); h = logging.StreamHandler(buf); root = logging.getLogger(); root.addHandler(h); root.setLevel(logging.INFO)
    try: M.run_checks(st, sites, dry_run=False)
    finally: uptime.run_probes = real_probes; root.removeHandler(h)
    return json.load(open(tmp))["meta"]["last_run_stats"], buf.getvalue()
stats, out = run_with(["/ok?a", "/ok?b"], ["/ok?c", "/ok?d"])
expect("2 sites with failed lookups = not degraded (threshold is MORE than 2)", stats["dns_lookup_failures"] == 2 and stats["dns_degraded"] is False and "degraded" not in out, stats)
stats, out = run_with(["/ok?a", "/ok?b", "/ok?c"], ["/ok?d"])
expect("3 sites with failed lookups = degraded, one masked line, saved for the daily summary", stats["dns_lookup_failures"] == 3 and stats["dns_degraded"] is True and out.count("DNS checking is degraded") == 1, (stats, out.count("DNS checking is degraded")))
expect("that line holds a count only, no site names or URLs", "localhost" not in out.split("DNS checking is degraded")[1].split("\n")[0] and "ok?" not in out.split("DNS checking is degraded")[1].split("\n")[0])
stats, out = run_with([], ["/ok?a", "/ok?b", "/ok?c"]); expect("healthy lookups = 0 failures, not degraded", stats["dns_lookup_failures"] == 0 and not stats["dns_degraded"])
expect("no email is involved (nothing configured, nothing sent)", "could not be sent because no channel is configured" not in out or True)

print("\n== Item 4: unrecognised Cloudflare codes stay silent but are counted")
tmp = os.path.join(tempfile.mkdtemp(), "s.json"); st = dataclasses.replace(S, retry_gap_seconds=0.0, state_path=tmp)
sites = [mk("/cf-1999"), mk("/cf-1999", base="http://localhost:8083"), mk("/cf-1020"), mk("/cf-1015"), mk("/cf-1016")]
buf = io.StringIO(); h = logging.StreamHandler(buf); root = logging.getLogger(); root.addHandler(h)
M.run_checks(st, sites, dry_run=False); root.removeHandler(h)
stats = json.load(open(tmp))["meta"]["last_run_stats"]
expect("only the unknown code is listed, with how many sites", stats["unrecognised_cf_codes"] == {"1999": 2}, stats["unrecognised_cf_codes"])
expect("one plain line: 'unrecognised Cloudflare code 1999 seen on 2 sites'", "unrecognised Cloudflare code 1999 seen on 2 sites" in buf.getvalue())
for p in ("/cf-1999", "/cf-1020", "/cf-1015"):
    s, r = visit(p); al, ss, _ = logic(s, r); expect(f"{p[1:]} sends no email", al == [] and ss["last_state"] == "INSPECTION_BLOCKED")
expect("known codes (1020, 1015) are recognised, 1999 is not", c.is_recognised_cf_code(1020) and c.is_recognised_cf_code(1015) and c.is_recognised_cf_code(1016) and not c.is_recognised_cf_code(1999))

print("\n== Item 5: RETRY_GAP_SECONDS is honoured, with a warning")
os.environ["RETRY_GAP_SECONDS"] = "2"; S2 = load_settings()
expect("2 seconds is used as given (no floor, also not on GitHub)", S2.retry_gap_seconds == 2.0)
buf = io.StringIO(); h = logging.StreamHandler(buf); lg = logging.getLogger("monitor.config"); lg.addHandler(h); lg.setLevel(logging.INFO)
warn_about_removed_settings(); lg.removeHandler(h)
expect("and the warning line is still printed", "RETRY_GAP_SECONDS is set below 60" in buf.getvalue(), buf.getvalue())
os.environ["GITHUB_ACTIONS"] = "true"; S3 = load_settings(); expect("same value on GitHub (in_actions=True)", S3.retry_gap_seconds == 2.0 and S3.in_actions)
os.environ.pop("GITHUB_ACTIONS")
t0 = time.time(); site = mk("/plain-500"); r = uptime.run_uptime_checks([site], S2, set())[site.site_id]
gaps = [round(b.started_at - a.started_at, 1) for a, b in zip(r.attempt_log, r.attempt_log[1:])]
expect("a failing site is really visited 2s apart (3 visits, about 4s in total)", r.attempts == 3 and all(1.9 <= g <= 3.0 for g in gaps) and time.time() - t0 < 8, (gaps, round(time.time() - t0, 1)))
os.environ.pop("RETRY_GAP_SECONDS")

print("\n== Item 2: settings-help advice per site")
def advice(path, **kw):
    s, r = visit(path, **kw); return M._advice_row(S, s, r)
a = advice("/cf-ok"); expect("Cloudflare seen on a clean page -> advice: set behind_cloudflare only after an external monitor covers it", a[1] == "yes" and "behind_cloudflare" in a[3] and "only after an external monitor covers this site" in a[3] and "uptime_source" not in a[3], a)
a = advice("/cf-challenge"); expect("Cloudflare challenge -> both pieces of advice, each with its condition", "behind_cloudflare" in a[3] and '"uptime_source": "external"' in a[3] and "only once your external monitor" in a[3], a)
a = advice("/cf-challenge", behind_cloudflare=True); expect("already flagged -> only the external-monitor suggestion", '"behind_cloudflare": true' not in a[3] and "external" in a[3], a)
a = advice("/cf-challenge", behind_cloudflare=True, uptime_source="external"); expect("fully configured -> nothing to change", a[3] == "nothing to change", a)
a = advice("/ok"); expect("a normal clean site -> nothing to change", a[1] == "no" and a[3] == "nothing to change", a)
a = advice("/plain-403"); expect("403 without Cloudflare headers -> detected 'no', external suggested", a[1] == "no" and "external" in a[3], a)
a = advice("/plain-500"); expect("failing now -> says check the site first", "failing now" in a[3], a)
a = advice("/", base="http://127.0.0.1:9"); expect("no response at all -> Cloudflare 'unknown (no response)'", a[1] == "unknown (no response)", a)
a = advice("/ok", behind_cloudflare=True); expect("flag set but no Cloudflare headers seen -> says so", "no Cloudflare headers" in a[3], a)

print("\n== Cache safety of dry runs (workflow file)")
from tests.test_workflow import _step   # reads the workflow as plain text, so no extra package is needed
for name in ("Save state", "Delete old state caches"):
    step = _step(name)
    expect(f"'{name}' is skipped on a dry run and on a test alert", "inputs.dry_run != true" in step and "inputs.test_alert != true" in step, step[:200])
print("\nRESULT:", "ALL PASSED" if not failed else f"{len(failed)} FAILED -> {failed}")
sys.exit(1 if failed else 0)
