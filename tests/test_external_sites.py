"""Sites an external monitor owns still get 5xx and timeout warnings. Run with:  python -m unittest discover -s tests"""

import time
import unittest

from monitor.checks import uptime
from monitor.logic import evaluate_uptime
from monitor.state import get_site_state
from tests.helpers import CF, FakeSites, make_settings, make_site


def _run(route, **site_kwargs):
    server = FakeSites({"/": route})
    try:
        settings = make_settings()
        site = make_site(server.base + "/", **site_kwargs)
        result = uptime.run_uptime_checks([site], settings, set(), sleep=lambda s: None)[site.site_id]
        state = {"meta": {}, "sites": {}}
        site_state = get_site_state(state, site.site_id)
        alerts = evaluate_uptime(site, site_state, result, time.time(), settings)
        return result, site_state, [a.kind for a in alerts]
    finally:
        server.close()


EXTERNAL = dict(uptime_source="external")


class ExternalSiteTests(unittest.TestCase):
    def test_503_through_cloudflare_warns(self):
        _, site_state, kinds = _run((503, CF, b"down"), **EXTERNAL)
        self.assertEqual(kinds, ["WARNING"])
        self.assertEqual(site_state["last_state"], "WARNING")

    def test_plain_503_without_cloudflare_headers_warns(self):
        # No cf-ray anywhere. Before this change an external site stayed completely silent here.
        _, site_state, kinds = _run((503, {}, b"down"), **EXTERNAL)
        self.assertEqual(kinds, ["WARNING"])
        self.assertEqual(site_state["status"], "up")

    def test_plain_500_without_cloudflare_headers_warns(self):
        self.assertEqual(_run((500, {}, b"boom"), **EXTERNAL)[2], ["WARNING"])

    def test_timeout_warns(self):
        result, _, kinds = _run(("hang", {}, b"slow"), **EXTERNAL)
        self.assertEqual(kinds, ["WARNING"])
        self.assertEqual({a.signal for a in result.attempt_log}, {"TIMEOUT"})

    def test_external_monitor_still_owns_down(self):
        # 5xx and timeouts are never DOWN on an external site. A Cloudflare 522 on all visits still is.
        result, site_state, kinds = _run((503, {}, b"x"), **EXTERNAL)
        self.assertNotEqual(site_state["status"], "down")
        _, _, kinds = _run((522, CF, b"x"), **EXTERNAL)
        self.assertEqual(kinds, ["DOWN"])

    def test_a_404_on_an_external_site_stays_silent(self):
        self.assertEqual(_run((404, {}, b"gone"), **EXTERNAL)[2], [])

    def test_self_sites_keep_their_stage_1_behaviour(self):
        self.assertEqual(_run((503, {}, b"down"))[2], ["DOWN"])
        self.assertEqual(_run(("hang", {}, b"slow"))[2], ["DOWN"])


if __name__ == "__main__":
    unittest.main()
