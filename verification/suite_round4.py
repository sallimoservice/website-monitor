import dataclasses, os, sys, time
import _paths
for k in list(os.environ):
    if k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS", "STAGGER_SECONDS"): os.environ.pop(k)
os.environ["NO_PROXY"] = "*"; os.environ["STATE_SALT"] = "t"
from monitor.config import load_settings, Site, make_site_id
from monitor.checks import classify as c, uptime
from monitor.logic import evaluate_uptime
from monitor.state import get_site_state
import cf_server; cf_server.start()
S = load_settings(); failed = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else ""))
    if not cond: failed.append(label)
def mk(path, **kw):
    url = "http://127.0.0.1:8083" + path
    return Site(index=1, name=path, url=url, site_id=make_site_id("t", url), expected_domain="x", **kw)

print("== Stagger: 17 sites do not all start in the same second")
sites = [mk(f"/ok?s={i}") for i in range(17)]
uptime._rng.seed(7); sleeps = []
res = uptime.run_uptime_checks(sites, dataclasses.replace(S, stagger_seconds=10.0), set(), sleep=sleeps.append)
expect("default stagger is 20 seconds", S.stagger_seconds == 20.0, S.stagger_seconds)
expect("every first visit gets its own random pause between 0 and 10s", len(sleeps) == 17 and all(0 < x <= 10 for x in sleeps), sleeps)
expect("the pauses are spread out, not all equal (spread > 4s)", max(sleeps) - min(sleeps) > 4, (min(sleeps), max(sleeps)))
sleeps2 = []; uptime.run_uptime_checks(sites, dataclasses.replace(S, stagger_seconds=0.0), set(), sleep=sleeps2.append)
expect("STAGGER_SECONDS=0 switches it off", sleeps2 == [])
expect("all 17 healthy sites still got their single visit", all(r.verdict == c.VERDICT_NOT_DOWN and r.attempts == 1 for r in res.values()))

print("\n== Rest floor: a site that just timed out is not hit again straight away")
real = uptime.check_once; uptime.check_once = lambda site, settings: uptime.UptimeResult(started_at=0.0, finished_at=0.0)
T = 1_000_000.0; site = mk("/ok")
slow_prev = uptime.UptimeResult(started_at=T, finished_at=T + 58)       # a visit that dragged on for 58 seconds
w = []; uptime._attempt(site, dataclasses.replace(S, retry_gap_seconds=60.0), slow_prev, w.append, lambda: T + 58)
expect("58s visit, 60s rule: waits another 15s (not 2s)", w == [15.0], w)
fast_prev = uptime.UptimeResult(started_at=T, finished_at=T + 1)
w = []; uptime._attempt(site, dataclasses.replace(S, retry_gap_seconds=60.0), fast_prev, w.append, lambda: T + 1)
expect("1s visit: still waits until 60s after it started", w == [59.0], w)
w = []; uptime._attempt(site, dataclasses.replace(S, retry_gap_seconds=2.0), slow_prev, w.append, lambda: T + 58)
expect("with RETRY_GAP_SECONDS=2 the rest floor shrinks to 2s (testing stays quick)", w == [2.0] or w == [], w)
uptime.check_once = real
r = uptime.run_uptime_checks([mk("/plain-500")], dataclasses.replace(S, retry_gap_seconds=1.0, stagger_seconds=0.0), set())[mk("/plain-500").site_id]
log = r.attempt_log
expect("one site, three visits: strictly one after another, never overlapping", len(log) == 3 and all(b.started_at >= a.finished_at for a, b in zip(log, log[1:])), [(round(a.started_at % 100, 2), round(a.finished_at % 100, 2)) for a in log])

print("\n== Requests one run makes to one site (counted at the server)")
def count(path, **kw):
    time.sleep(0.5)                                  # let connections from the previous scenario finish arriving
    for k in list(cf_server.hits): cf_server.hits.pop(k)
    cf_server.conns["n"] = 0
    s = mk(path, **kw); uptime.run_uptime_checks([s], dataclasses.replace(S, retry_gap_seconds=0.0, stagger_seconds=0.0, text_recheck_gap_seconds=0.0), set())
    time.sleep(0.5)                                  # let the short TCP check connections reach the counter
    return sum(cf_server.hits.values()), cf_server.conns["n"]
for label, path, kw, want in (("healthy page", "/ok", {}, (1, 2)), ("Cloudflare challenge", "/cf-challenge", {}, (1, 2)), ("403 answer", "/plain-403", {}, (1, 2)),
                              ("HTTP 500 (failing)", "/plain-500", {}, (3, 6)), ("Cloudflare 1016", "/cf-1016", {}, (3, 6)), ("expected text missing", "/cf-ok-notext", {"expected_text": "Book a ride"}, (2, 4))):
    got = count(path, **kw); expect(f"{label}: {got[0]} request(s), {got[1]} connection(s) (GET + a TCP check each visit)", got == want, got)

print("\n== Overloaded origin behind Cloudflare")
def judge(path):
    s = mk(path); r = uptime.run_uptime_checks([s], dataclasses.replace(S, retry_gap_seconds=0.0, stagger_seconds=0.0), set())[s.site_id]
    st = {"meta": {}, "sites": {}}; ss = get_site_state(st, s.site_id)
    return r, evaluate_uptime(s, ss, r, time.time(), S), ss["last_state"]
for path, code in (("/cf-522", 522), ("/cf-524", 524), ("/cf-521", 521)):
    r, al, state = judge(path); expect(f"{code} -> CF_ORIGIN_ERROR -> DOWN email after 3 visits", r.signal == c.CF_ORIGIN_ERROR and r.attempts == 3 and len(al) == 1 and al[0].kind == "DOWN" and state == "DOWN", (r.signal, r.attempts, state))
for path, code in (("/cf-502", 502), ("/cf-504", 504), ("/cf-503", 503)):
    r, al, state = judge(path); expect(f"{code} behind Cloudflare -> ORIGIN_5XX -> one WARNING after 3 visits (never DOWN), label {state}", r.signal == c.ORIGIN_5XX and r.attempts == 3 and len(al) == 1 and al[0].kind == "WARNING" and r.verdict != c.VERDICT_DOWN and state == "WARNING", (r.signal, [a.kind for a in al], state))
print("\nRESULT:", "ALL PASSED" if not failed else f"{len(failed)} FAILED -> {failed}")
sys.exit(1 if failed else 0)
