import contextlib, dataclasses, io, os, sys, time
import _paths
for k in list(os.environ):
    if k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS", "STAGGER_SECONDS"): os.environ.pop(k)
os.environ["NO_PROXY"] = "*"; os.environ["STATE_SALT"] = "t"; os.environ["STAGGER_SECONDS"] = "0"
from monitor.config import load_settings, Site, make_site_id
from monitor.checks import classify as c, uptime, network
from monitor.logic import evaluate_uptime, apply_delivery
from monitor.state import get_site_state
from monitor import main as M
import cf_server; cf_server.start()
S = load_settings(); FAST = dataclasses.replace(S, retry_gap_seconds=0.0, read_timeout=1.0)
failed = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else ""))
    if not cond: failed.append(label)
def mk(path, **kw):
    url = "http://127.0.0.1:8083" + path
    return Site(index=1, name=path, url=url, site_id=make_site_id("t", url), expected_domain="x", **kw)
def visit(path, settings=FAST, **kw):
    s = mk(path, **kw); return s, uptime.run_uptime_checks([s], settings, set(), sleep=lambda x: None)[s.site_id]
def logic(s, r, st=None, now=None):
    st = st or {"meta": {}, "sites": {}}; ss = get_site_state(st, s.site_id)
    return evaluate_uptime(s, ss, r, now or time.time(), S), ss, st

print("== 1. A real challenge and a passed-through 503 land in DIFFERENT buckets")
s1, r1 = visit("/cf-503-iuam", behind_cloudflare=True); al1, ss1, _ = logic(s1, r1)
s2, r2 = visit("/cf-503", behind_cloudflare=True); al2, ss2, _ = logic(s2, r2)
print(f"      same status (503) and same cf-ray header on both:")
print(f"        real challenge page  ->  signal {r1.signal:11} label {ss1['last_state']:19} visits {r1.attempts}  emails {len(al1)}  ({r1.marker})")
print(f"        passed-through 503   ->  signal {r2.signal:11} label {ss2['last_state']:19} visits {r2.attempts}  emails {len(al2)}")
expect("503 + challenge page = CHALLENGE, silent, 1 visit, INSPECTION_BLOCKED", r1.signal == c.CHALLENGE and al1 == [] and ss1["last_state"] == "INSPECTION_BLOCKED" and r1.attempts == 1)
expect("503 + cf-ray and nothing else = ORIGIN_5XX, confirmed on 3 visits, one WARNING", r2.signal == c.ORIGIN_5XX and r2.attempts == 3 and len(al2) == 1 and al2[0].kind == "WARNING" and ss2["last_state"] == "WARNING")
expect("the two never share a bucket", r1.signal != r2.signal)
s, r = visit("/cf-503-origin", behind_cloudflare=True); al, ss, _ = logic(s, r)
expect("a passed-through 503 whose HTML carries Cloudflare's harmless challenge-platform script is STILL ORIGIN_5XX", r.signal == c.ORIGIN_5XX and len(al) == 1, r.signal)
s, r = visit("/cf-403-orchestrate", behind_cloudflare=True); expect("a page that loads the real challenge scripts (orchestrate / chl_page) IS a challenge", r.signal == c.CHALLENGE, (r.signal, r.marker))
s, r = visit("/cf-challenge", behind_cloudflare=True); expect("cf-mitigated header is still a challenge", r.signal == c.CHALLENGE)
for path in ("/cf-403-plain", "/cf-429"):
    s, r = visit(path, behind_cloudflare=True); al, ss, _ = logic(s, r)
    expect(f"{path[4:7]} + cf-ray alone is NOT a challenge: HTTP_ERROR, silent, UNKNOWN", r.signal == c.HTTP_ERROR and al == [] and ss["last_state"] == "UNKNOWN", (r.signal, ss["last_state"]))

print("\n== 2. ORIGIN_5XX behind Cloudflare = WARNING after 3 of 3, never DOWN")
for path, code in (("/cf-502", 502), ("/cf-503", 503), ("/cf-504", 504), ("/cf-500-origin", 500)):
    s, r = visit(path, behind_cloudflare=True); al, ss, _ = logic(s, r)
    expect(f"{code}: one WARNING, no DOWN, label WARNING, status never 'down'", len(al) == 1 and al[0].kind == "WARNING" and ss["status"] != "down" and r.verdict == c.VERDICT_NOT_DOWN and ss["last_state"] == "WARNING", [a.kind for a in al])
print("      warning text:", al[0].summary)
d = dict(al[0].details); expect("it carries the evidence (cf-ray, 3 attempts)", "Cloudflare cf-ray" in d and "Attempt 3" in d, list(d))
s, r = visit("/cf-502", behind_cloudflare=True); al, ss, st = logic(s, r, now=1_000_000.0)
for a in al: apply_delivery(st, a, 1_000_000.0)
al2, _, _ = logic(s, r, st=st, now=1_000_000.0 + 300); expect("not repeated next run", al2 == [])
al3, _, _ = logic(s, r, st=st, now=1_000_000.0 + 9 * 3600); expect("repeated after 8 hours (same as a DOWN reminder)", len(al3) == 1)
_, okr = visit("/ok"); al4, ss4, _ = logic(s, okr, st=st, now=1_000_000.0 + 10 * 3600); expect("clears silently when the site is fine again", al4 == [] and ss4["origin_trouble_active"] is False and ss4["last_state"] == "UP")
s, r = visit("/cf-502", behind_cloudflare=True); expect("history records 'unknown', not up", logic(s, r)[1]["history"][-1][1] is None)
s, r = visit("/cf-502"); al, ss, _ = logic(s, r)
expect("Cloudflare AUTO-detected (flag not set): same WARNING, so leaving a site 'self' does not hide it", r.strict and len(al) == 1 and al[0].kind == "WARNING", (r.strict, [a.kind for a in al]))
s, r = visit("/cf-502", behind_cloudflare=True, uptime_source="external"); al, ss, _ = logic(s, r)
expect("site handed to an external monitor warns on 5xx (it owns DOWN, not visibility)", [a.kind for a in al] == ["WARNING"] and ss["last_state"] == "WARNING", [a.kind for a in al])
s, r = visit("/cf-522", behind_cloudflare=True, uptime_source="external"); al, _, _ = logic(s, r)
expect("...but a Cloudflare 522 still DOWN-alerts even for an external site", len(al) == 1 and al[0].kind == "DOWN")
s, r = visit("/cf-502-then-ok" if False else "/cf-521-then-ok", behind_cloudflare=True); expect("trouble once, then fine = silent", r.signal == c.OK and not r.origin_trouble_confirmed)
s, r = visit("/plain-503"); al, ss, _ = logic(s, r)
expect("a NON-Cloudflare self site: 503 is still a real DOWN after 3 (Stage 1 behaviour unchanged)", r.signal == c.HTTP_ERROR and r.verdict == c.VERDICT_DOWN and al[0].kind == "DOWN")

print("\n== 3. Timeouts")
s, r = visit("/hang", behind_cloudflare=True); al, ss, _ = logic(s, r)
expect("Cloudflare + self: 3 timeouts in a row = one WARNING (was silent before this fix), never DOWN", r.signal == c.TIMEOUT and r.attempts == 3 and r.origin_trouble_confirmed and len(al) == 1 and al[0].kind == "WARNING" and ss["status"] != "down", (r.attempts, [a.kind for a in al]))
print("      warning text:", al[0].summary)
s, r = visit("/cf-hang-once", behind_cloudflare=True); al, ss, _ = logic(s, r)
expect("one timeout then a good page = silent", r.signal == c.OK and al == [] and r.attempts == 2, (r.signal, r.attempts))
s, r = visit("/hang", behind_cloudflare=True, uptime_source="external"); al, ss, _ = logic(s, r)
expect("Cloudflare + external: timeout warns after 3/3", [a.kind for a in al] == ["WARNING"] and r.attempts == 3 and ss["last_state"] == "WARNING")
s, r = visit("/hang"); al, ss, _ = logic(s, r)
expect("NON-Cloudflare self site: 3 timeouts = DOWN, exactly as in Stage 1", r.verdict == c.VERDICT_DOWN and al[0].kind == "DOWN")

print("\n== 4. Mixed trouble is not silent either")
s, r = visit("/cf-trouble-mix", behind_cloudflare=True); al, ss, _ = logic(s, r)
signals = [a.signal for a in r.attempt_log]
expect("522, then 504, then a timeout = one WARNING (not silent, not DOWN)", signals == [c.CF_ORIGIN_ERROR, c.ORIGIN_5XX, c.TIMEOUT] and len(al) == 1 and al[0].kind == "WARNING" and r.verdict == c.VERDICT_NOT_DOWN, (signals, [a.kind for a in al]))
print("      warning text:", al[0].summary)
s, r = visit("/cf-522", behind_cloudflare=True); expect("all 522 is still a real DOWN", r.verdict == c.VERDICT_DOWN)
st = {"meta": {}, "sites": {}}; s, r = visit("/cf-trouble-mix", behind_cloudflare=True); ss = get_site_state(st, s.site_id)
ss.update(status="down", down_since=1000.0, down_notified_at=1000.0, down_signal=c.CF_ORIGIN_ERROR)
al = evaluate_uptime(s, ss, r, 1000.0 + 9 * 3600, S)
expect("a site already DOWN whose errors change kind keeps getting its 8-hour reminder", len(al) == 1 and al[0].kind == "DOWN" and al[0].headline == "STILL DOWN", [(a.kind, a.headline) for a in al])
expect("...and its recorded cause is not overwritten by the new kind", ss["down_signal"] == c.CF_ORIGIN_ERROR)

print("\n== 5. Who shares a server")
E = lambda label, addrs, cf=False, server="": {"label": label, "addresses": addrs, "cloudflare": cf, "server": server}
entries = [E("Site 01", ["104.18.1.1"], True, "cloudflare"), E("Site 02", ["104.18.1.1"], True, "cloudflare"), E("Site 03", ["93.184.1.5"], False, "LiteSpeed"),
           E("Site 04", ["93.184.1.5"], False, "LiteSpeed"), E("Site 05", ["93.184.1.5", "93.184.1.6"], False, "nginx"), E("Site 06", ["93.184.9.9"], False, "Apache"),
           E("Site 07", ["198.51.100.7"], False, ""), E("Site 08", ["198.51.100.7"], False, ""), E("Site 09", [], False, "")]
groups, cf, none = M.group_by_address(entries)
expect("sites that share an address are grouped (03, 04, 05 via the common address)", [g["labels"] for g in groups if "Site 03" in g["labels"]] == [["Site 03", "Site 04", "Site 05"]], groups)
expect("a second group forms separately (07, 08)", any(g["labels"] == ["Site 07", "Site 08"] for g in groups))
expect("a site alone on its address is not listed (06)", not any("Site 06" in g["labels"] for g in groups))
expect("Cloudflare sites are listed apart and never grouped with others", cf == ["Site 01", "Site 02"] and not any("Site 01" in g["labels"] for g in groups))
expect("a site with no address is listed apart", none == ["Site 09"])
expect("Server headers are collected per group", [g["servers"] for g in groups if "Site 03" in g["labels"]] == [["LiteSpeed", "nginx"]])
expect("Cloudflare address ranges are recognised (and a normal address is not)", network.is_cloudflare_address("104.18.2.3") and network.is_cloudflare_address("2606:4700::1111") and not network.is_cloudflare_address("93.184.216.34"))
def render(real):
    st_ = dataclasses.replace(S, real_names_in_logs=real); buf = io.StringIO()
    with contextlib.redirect_stdout(buf): M._print_hosting(st_, entries)
    return buf.getvalue()
pub, loc = render(False), render(True)
print("      --- public GitHub log version:"); print("\n".join("      " + l for l in pub.splitlines()))
expect("public log shows NO addresses", "93.184" not in pub and "198.51" not in pub and "104.18" not in pub)
expect("on your own PC the addresses are shown", "93.184.1.5" in loc)

print("\n== 5b. The Cloudflare label comes from evidence, not from the config flag")
fake_probes = lambda addrs: uptime.UptimeResult(probes=network.Probes(addresses=addrs), attempts=1)
site_flagged = mk("/x", behind_cloudflare=True)
e = M._hosting_entry(S, site_flagged, fake_probes(["93.184.1.5"]), {"cloudflare_seen": False}); expect("flagged in config but resolving to a normal address and never seen with Cloudflare headers = NOT Cloudflare", e["cloudflare"] is False, e)
e = M._hosting_entry(S, mk("/x"), fake_probes(["104.18.3.4", "172.67.1.2"]), {"cloudflare_seen": False}); expect("all addresses inside Cloudflare's ranges = Cloudflare", e["cloudflare"] is True)
e = M._hosting_entry(S, mk("/x"), fake_probes(["104.18.3.4", "93.184.1.5"]), {"cloudflare_seen": False}); expect("a mix of Cloudflare and other addresses = not labelled Cloudflare", e["cloudflare"] is False)
e = M._hosting_entry(S, mk("/x"), fake_probes(["93.184.1.5"]), {"cloudflare_seen": True}); expect("seen behind Cloudflare on an earlier run = Cloudflare", e["cloudflare"] is True)
_, cfl, none = M.group_by_address([{"label": "Site 15", "addresses": [], "cloudflare": True, "server": ""}]); expect("a site with no address is 'no address found' even if Cloudflare was guessed", none == ["Site 15"] and cfl == [])

print("\n== 6. SETTINGS HELP wording")
s, r = visit("/cf-ok"); a = M._advice_row(S, s, r)
expect("Cloudflare detected -> 'set behind_cloudflare only after an external monitor covers this site'", "only after an external monitor covers this site" in a[3] and "uptime_source" not in a[3], a[3])
s, r = visit("/cf-challenge"); a = M._advice_row(S, s, r)
expect("challenged site -> external-monitor advice says 'green ... for a day'", "only once your external monitor has been green" in a[3] and "only after an external monitor covers this site" in a[3], a[3])
s, r = visit("/cf-502", behind_cloudflare=True); a = M._advice_row(S, s, r); expect("origin trouble -> 'check this site first'", "in trouble" in a[3] and "check this site first" in a[3], a[3])
print("\nRESULT:", "ALL PASSED" if not failed else f"{len(failed)} FAILED -> {failed}")
sys.exit(1 if failed else 0)
