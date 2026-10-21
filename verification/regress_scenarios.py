"""Run the same scenarios through whichever version of the code is first on PYTHONPATH. Prints JSON."""
import dataclasses, json, os, sys, time
os.environ["NO_PROXY"] = "*"; os.environ["STATE_SALT"] = "t"
for k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS"): os.environ.pop(k, None)
import cf_server; cf_server.start()
from monitor.config import load_settings, Site, make_site_id
from monitor.checks.uptime import check_site
from monitor.logic import evaluate_uptime, apply_delivery
from monitor.state import get_site_state
try:                                            # Stage A only: no real DNS here, so stand in for 1.1.1.1 / 8.8.8.8
    from monitor.checks import network
    network._doh_query = lambda url, host, rtype: "NXDOMAIN" if host.endswith(".invalid") else "OK"
except ImportError:
    pass
S = load_settings()
def short(s):                                   # shorter timeout for the timeout scenario
    for f in ("request_timeout", "read_timeout"):
        if hasattr(s, f): s = dataclasses.replace(s, **{f: 1.0})
    return s
B, H = "http://127.0.0.1:8083", 3600
T = 1_800_000_000.0
SCEN = [  # name, runs [(offset_seconds, base+path)], site kwargs, settings tweak
    ("HTTP 500", [(0, B+"/plain-500"), (300, B+"/plain-500"), (7*H, B+"/plain-500"), (9*H, B+"/plain-500")], {}, None),
    ("HTTP 404", [(0, B+"/plain-404"), (300, B+"/plain-404")], {}, None),
    ("HTTP 410", [(0, B+"/plain-410"), (300, B+"/plain-410")], {}, None),
    ("HTTP 503", [(0, B+"/plain-503"), (300, B+"/plain-503")], {}, None),
    ("timeout", [(0, B+"/hang"), (300, B+"/hang")], {}, short),
    ("connection refused", [(0, "http://127.0.0.1:9/"), (300, "http://127.0.0.1:9/")], {}, None),
    ("refused + per-site flag", [(0, "http://127.0.0.1:9/"), (300, "http://127.0.0.1:9/")], {"connection_refused_is_warning": True}, None),
    ("domain does not exist", [(0, "http://gone-example.invalid/"), (300, "http://gone-example.invalid/")], {}, None),
    ("certificate invalid", [(0, "https://127.0.0.1:8443/ok"), (300, "https://127.0.0.1:8443/ok")], {}, None),
    ("slow page (4s, limit 1s)", [(0, B+"/hang"), (300, B+"/hang")], {"slow_threshold_seconds": 1.0}, None),
    ("HTTP 401", [(0, B+"/plain-401"), (300, B+"/plain-401")], {}, None),
    ("HTTP 403", [(0, B+"/plain-403"), (300, B+"/plain-403")], {}, None),
    ("HTTP 405", [(0, B+"/plain-405")], {}, None),
    ("HTTP 429", [(0, B+"/plain-429")], {}, None),
    ("recovered (500 then OK)", [(0, B+"/plain-500"), (300, B+"/plain-500"), (H, B+"/ok")], {}, None),
]
out = {}
for name, runs, kw, tweak in SCEN:
    st = {"meta": {}, "sites": {}}
    sid = make_site_id("t", name)
    settings = tweak(S) if tweak else S
    row = []
    for offset, url in runs:
        site = Site(index=1, name=name, url=url, site_id=sid, expected_domain="x", **kw)
        res = check_site(site, settings, sleep=lambda s: None)
        ss = get_site_state(st, sid)
        alerts = evaluate_uptime(site, ss, res, T + offset, settings)
        for a in alerts: apply_delivery(st, a, T + offset)
        row.append([offset, [f"{a.kind}{'-reminder' if a.headline else ''}" for a in alerts], [dict(a.details).get("Downtime") for a in alerts if a.kind == "RECOVERED"]])
    out[name] = row
print(json.dumps(out))
