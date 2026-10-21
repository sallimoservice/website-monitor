"""connection_refused_is_warning over time: warn once, remind daily, cool down, retry when undelivered.

Ported from the Stage 1 script to today's result objects. A fixed clock is used on purpose (seconds from an
arbitrary start), so nothing here depends on the calendar.
"""
import _paths
import json
import os
import sys

for k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "SMTP_USER"):
    os.environ.pop(k, None)
from monitor.alerts import DOWN, RECOVERED, WARNING
from monitor.checks import classify as c
from monitor.checks.uptime import UptimeResult
from monitor.config import ConfigError, Site, load_settings, load_sites
from monitor.logic import apply_delivery, evaluate_uptime
from monitor.state import get_site_state

s = load_settings()
failures = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if detail and not cond else ""))
    if not cond: failures.append(label)

HOUR, DAY = 3600, 86400
REFUSED = lambda: UptimeResult(signal=c.CONN_FAIL, verdict=c.VERDICT_DOWN, attempts=3, error="Connection refused")
OK = lambda: UptimeResult(signal=c.OK, status_code=200, response_time=0.5)
def failure(signal, status=None): return UptimeResult(signal=signal, verdict=c.VERDICT_DOWN, status_code=status, attempts=3, error=signal)
def site(flag): return Site(index=1, name="SRTC Limo", url="https://srtc.example.com", site_id="abc", expected_domain="srtc.example.com", connection_refused_is_warning=flag)
def fresh(): return {"meta": {}, "sites": {}}
def step(st, sit, result, now, deliver=True):
    ss = get_site_state(st, sit.site_id)
    alerts = evaluate_uptime(sit, ss, result, now, s)
    if deliver:
        for a in alerts: apply_delivery(st, a, now)
    return alerts, ss

print("-- config")
os.environ["SITES_JSON"] = json.dumps([{"name": "A", "url": "https://a.example.com"}])
expect("default is OFF", load_sites(s)[0].connection_refused_is_warning is False)
os.environ["SITES_JSON"] = json.dumps([{"name": "A", "url": "https://a.example.com", "connection_refused_is_warning": True}])
expect("true is accepted", load_sites(s)[0].connection_refused_is_warning is True)
os.environ["SITES_JSON"] = json.dumps([{"name": "A", "url": "https://a.example.com", "connection_refused_is_warning": "false"}])
import logging
records = []
class _Catch(logging.Handler):
    def emit(self, record): records.append(record.getMessage())
catch = _Catch(); logging.getLogger().addHandler(catch)
try:
    load_sites(s); expect('quoted "false" is rejected', False)
except ConfigError:
    expect('quoted "false" is rejected: the entry is skipped with a clear message (and with nothing else left, the run stops)',
           any("must be true or false" in m for m in records), records)
logging.getLogger().removeHandler(catch)
example = json.load(open(_paths.ROOT / "sites.example.json"))
expect("example file does not enable it for any site", not any(x.get("connection_refused_is_warning") for x in example))

print("\n-- setting OFF, refusal is a normal DOWN")
st = fresh(); al, ss = step(st, site(False), REFUSED(), 1000)
expect("DOWN alert", len(al) == 1 and al[0].kind == DOWN and ss["status"] == "down")

print("\n-- setting ON")
st = fresh(); sit = site(True); t = 1000
al, ss = step(st, sit, REFUSED(), t)
expect("first refusal gives ONE WARNING, no DOWN", len(al) == 1 and al[0].kind == WARNING and al[0].tag == "refused", [a.kind for a in al])
expect("site is NOT marked down", ss["status"] != "down" and ss["down_since"] is None, ss["status"])
al, _ = step(st, sit, REFUSED(), t + 300);        expect("5 min later, still refused -> silent", al == [])
al, _ = step(st, sit, REFUSED(), t + 6 * HOUR);   expect("6 hours later -> still silent", al == [])
al, _ = step(st, sit, REFUSED(), t + DAY + 60);   expect("after 24h -> one reminder warning", len(al) == 1 and al[0].kind == WARNING)
al, ss = step(st, sit, OK(), t + DAY + 400);      expect("site answers again -> no RECOVERED alert (it was never DOWN)", all(a.kind != RECOVERED for a in al) and ss["refused_active"] is False, [a.kind for a in al])
al, _ = step(st, sit, REFUSED(), t + DAY + 700);  expect("refused again 5 min after the last warning -> silent (1h flapping cooldown)", al == [])
al, _ = step(st, sit, OK(), t + DAY + 800)
al, _ = step(st, sit, REFUSED(), t + DAY + 2 * HOUR + 900); expect("new episode after the cooldown -> warns again", len(al) == 1 and al[0].kind == WARNING)

print("\n-- undelivered warning is retried")
st = fresh(); al, _ = step(st, sit, REFUSED(), 1000, deliver=False)
al2, _ = step(st, sit, REFUSED(), 1300);          expect("email failed -> warning sent again next run", len(al) == 1 and len(al2) == 1)
al3, _ = step(st, sit, REFUSED(), 1600);          expect("then delivered -> quiet", al3 == [])

print("\n-- other failures are NEVER downgraded, even with the setting ON")
for label, result in (("timeout", failure(c.TIMEOUT)), ("DNS failure", failure(c.DNS_FAIL)), ("HTTP 500", failure(c.HTTP_ERROR, 500))):
    st = fresh(); al, ss = step(st, sit, result, 1000)
    expect(f"{label} -> DOWN", len(al) == 1 and al[0].kind == DOWN and ss["status"] == "down", [a.kind for a in al])
st = fresh(); al, ss = step(st, sit, UptimeResult(signal=c.TLS_WARN, verdict=c.VERDICT_NOT_DOWN, error="certificate"), 1000)
expect("a certificate problem is a WARNING (approved change from Stage 1, where it was DOWN), never the refused path", [a.kind for a in al] == [WARNING] and al[0].tag == "tls", [a.tag for a in al])

print("\n-- a site that is already DOWN stays in the DOWN flow")
st = fresh(); al, ss = step(st, sit, failure(c.HTTP_ERROR, 500), 1000)
al, ss = step(st, sit, REFUSED(), 1300)
expect("DOWN (HTTP 500) then refused -> still DOWN, no extra warning", ss["status"] == "down" and al == [], (ss["status"], [a.kind for a in al]))
al, ss = step(st, sit, OK(), 1600); expect("then recovers -> normal RECOVERED", len(al) == 1 and al[0].kind == RECOVERED)

print("\nRESULT:", "ALL PASSED" if not failures else f"{len(failures)} FAILED -> {failures}")
sys.exit(1 if failures else 0)
