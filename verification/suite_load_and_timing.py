"""How much load one run puts on a site, and how long a bad run takes.

Part 1 counts what one run does to ONE site: page requests and TCP connections (each visit also makes one
TCP probe, plus a TLS probe on https sites). The cap is 5 page requests per site per run.
Part 2 runs 17 sites at 1/10 of the production timings (connect 1s, read 3s, gap 6s, stagger 2s) with 0, 5 and
17 of them hanging, to show that the run takes about as long for 5 hanging sites as for 17, because visits run
in parallel. Multiply the wall time by about 10 for production. (Fixed costs do not scale, so treat it as a bound.)
"""
import _paths
import dataclasses
import os
import sys
import time

for k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS", "STAGGER_SECONDS"): os.environ.pop(k, None)
os.environ["NO_PROXY"] = "*"; os.environ["STATE_SALT"] = "t"; os.environ["STAGGER_SECONDS"] = "0"
import cf_server
cf_server.start()
from monitor.checks import uptime
from monitor.checks.uptime import check_site
from monitor.config import Site, load_settings, make_site_id

S = load_settings()
failed = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else ""))
    if not cond: failed.append(label)

print("== 1. Requests per site per run")
cases = (("healthy", "/ok", {}, 1), ("challenge page", "/cf-challenge", {}, 1), ("403 answer", "/plain-403", {}, 1),
         ("failing (HTTP 500)", "/plain-500", {}, 3), ("page without the expected text", "/cf-ok-notext", {"expected_text": "Book a ride"}, 2),
         ("timeout", "/hang", {}, 3), ("connection refused", None, {}, 0))
for label, path, kw, pages in cases:
    url = "http://127.0.0.1:9/" if path is None else "http://127.0.0.1:8083" + path
    site = Site(index=1, name=label, url=url, site_id=make_site_id("t", label), expected_domain="x", **kw)
    time.sleep(0.4)
    cf_server.hits.clear(); cf_server.conns["n"] = 0
    settings = dataclasses.replace(S, read_timeout=1.0, retry_gap_seconds=0.0, text_recheck_gap_seconds=0.0)
    check_site(site, settings, sleep=lambda x: None)
    time.sleep(0.4)
    made, conns = sum(cf_server.hits.values()), cf_server.conns["n"]
    print(f"      {label:34} {made} page request(s), {conns} connection(s)")
    expect(f"{label}: {pages} page request(s), within the cap of 5", made == pages and made <= 5, made)
    expect(f"{label}: connections = page requests + one TCP probe per visit", conns == (made * 2 if made else 0), conns)

print("\n== 2. A run with sites that hang (1/10 scale)")
SCALED = dataclasses.replace(S, connect_timeout=1.0, read_timeout=3.0, retry_gap_seconds=6.0, stagger_seconds=2.0)
def run(n_hang, n_total=17):
    sites = []
    for i in range(n_total):
        url = "http://127.0.0.1:8083" + (f"/cf-hang?n={i}" if i < n_hang else f"/cf-ok?n={i}")
        sites.append(Site(index=i + 1, name=f"s{i}", url=url, site_id=make_site_id("t", url), expected_domain="x", behind_cloudflare=True))
    start = time.time()
    results = uptime.run_uptime_checks(sites, SCALED, set())
    return time.time() - start, sum(r.requests_made for r in results.values() if r)
(t0, v0), (t5, v5), (t17, v17) = run(0), run(5), run(17)
print(f"      0 hang {t0:.1f}s ({v0} visits)   5 hang {t5:.1f}s ({v5} visits)   17 hang {t17:.1f}s ({v17} visits)")
expect("no hanging site: the whole run is quick", t0 < 15, t0)
expect("visit counts: 17, 27, 51", (v0, v5, v17) == (17, 27, 51), (v0, v5, v17))
expect("hanging sites cost about 3 visits and 2 gaps (12s plus a visit) at this scale", 12 <= t5 <= 60, t5)
expect("5 hanging sites take about as long as 17 (parallel visits)", abs(t17 - t5) < 10, (t5, t17))
print("\nRESULT:", "ALL PASSED" if not failed else f"{len(failed)} FAILED -> {failed}")
sys.exit(1 if failed else 0)
