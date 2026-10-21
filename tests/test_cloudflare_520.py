"""HTTP 520 is a warning, never DOWN. 521 to 526 stay DOWN. Run with:  python -m unittest discover -s tests"""

import time
import unittest

from monitor.checks import classify as c
from monitor.checks import uptime
from monitor.logic import evaluate_uptime
from monitor.state import get_site_state
from tests.helpers import CF, FakeSites, make_settings, make_site


def _verdict_for(status, behind_cloudflare=True):
    """Three real visits to a local site answering `status` with Cloudflare headers, then the alert logic."""
    server = FakeSites({"/": (status, CF, b"<html>error</html>")})
    try:
        settings = make_settings()
        site = make_site(server.base + "/", behind_cloudflare=behind_cloudflare)
        result = uptime.run_uptime_checks([site], settings, set(), sleep=lambda s: None)[site.site_id]
        state = {"meta": {}, "sites": {}}
        site_state = get_site_state(state, site.site_id)
        alerts = evaluate_uptime(site, site_state, result, time.time(), settings)
        return result, site_state, alerts
    finally:
        server.close()


class Cloudflare520Tests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(c.classify_response(520, CF, "").signal, c.CF_ORIGIN_UNKNOWN)
        for status in (521, 522, 523, 524, 525, 526):
            self.assertEqual(c.classify_response(status, CF, "").signal, c.CF_ORIGIN_ERROR, status)

    def test_three_520s_warn_and_are_not_down(self):
        result, site_state, alerts = _verdict_for(520)
        self.assertEqual([a.kind for a in alerts], ["WARNING"])
        self.assertNotEqual(result.verdict, c.VERDICT_DOWN)
        self.assertEqual(site_state["status"], "up")
        self.assertEqual(site_state["last_state"], "WARNING")
        text = " ".join(f"{k} {v}" for a in alerts for k, v in a.details)
        self.assertIn("firewall may be rejecting this monitor", text)

    def test_three_522s_are_down(self):
        result, site_state, alerts = _verdict_for(522)
        self.assertEqual([a.kind for a in alerts], ["DOWN"])
        self.assertEqual(result.verdict, c.VERDICT_DOWN)
        self.assertEqual(site_state["status"], "down")

    def test_every_521_to_526_is_down(self):
        for status in (521, 523, 524, 525, 526):
            result, _, alerts = _verdict_for(status)
            self.assertEqual(result.verdict, c.VERDICT_DOWN, status)
            self.assertEqual([a.kind for a in alerts], ["DOWN"], status)

    def test_a_mix_of_520_and_522_is_trouble_not_down(self):
        site = make_site("http://127.0.0.1:9/", behind_cloudflare=True)
        attempts = [uptime.UptimeResult(signal=s, status_code=code, cloudflare=True)
                    for s, code in ((c.CF_ORIGIN_ERROR, 522), (c.CF_ORIGIN_UNKNOWN, 520), (c.CF_ORIGIN_ERROR, 522))]
        self.assertNotEqual(c.compute_verdict(site, attempts, True, 3), c.VERDICT_DOWN)
        self.assertTrue(c.origin_trouble_confirmed(site, attempts, True, 3))


if __name__ == "__main__":
    unittest.main()
