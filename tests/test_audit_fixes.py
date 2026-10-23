"""Tests for the bugs found in the code audit. Run with:  python -m unittest discover -s tests"""

import contextlib
import dataclasses
import io
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from monitor import main as main_module
from monitor import state as state_store
from monitor.checks import classify as c
from monitor.checks import network
from monitor.checks.uptime import UptimeResult
from monitor.config import ConfigError, load_settings, load_sites_report
from monitor.logic import apply_delivery, evaluate_uptime
from tests.helpers import FakeSites, make_settings, make_site


def _good_site_state():
    entry = {}
    for key, default in state_store.DEFAULT_SITE_STATE.items():
        entry[key] = json.loads(json.dumps(default))
    entry["history"] = [[1000, 1, 120], [2000, 0, None], [3000, None, None]]
    entry["last_up_at"] = 1000.5
    entry["down_signal"] = "CONN_FAIL"
    entry["pending_recovery"] = {"down_since": 1, "recovered_at": 2, "last_up_at": 1}
    return entry


class StateRepairTests(unittest.TestCase):
    def _load(self, content):
        path = os.path.join(tempfile.mkdtemp(), "state.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content if isinstance(content, str) else json.dumps(content))
        return state_store.load_state(path)

    def test_a_good_state_is_left_alone(self):
        state = {"version": 2, "meta": {"last_run": 5, "created": 1}, "sites": {"a": _good_site_state()}}
        before = json.dumps(state, sort_keys=True)
        self.assertEqual(state_store.repair_state(state), 0)
        self.assertEqual(json.dumps(state, sort_keys=True), before)

    def test_wrong_types_are_reset_and_the_rest_is_kept(self):
        bad = _good_site_state()
        bad.update(history="oops", down_since="yesterday", down_notified_at="x", slow_active="yes", status=7, pending_recovery="no")
        state = self._load({"version": 2, "meta": [], "sites": {"keep": _good_site_state(), "bad": bad, "str": "x", "num": 5}})
        self.assertEqual(set(state["sites"]), {"keep", "bad"})          # entries that are not objects are dropped
        repaired = state["sites"]["bad"]
        self.assertEqual(repaired["history"], [])
        self.assertIsNone(repaired["down_since"])
        self.assertIsNone(repaired["down_notified_at"])
        self.assertIs(repaired["slow_active"], False)
        self.assertEqual(repaired["status"], "unknown")
        self.assertIsNone(repaired["pending_recovery"])
        self.assertEqual(state["sites"]["keep"]["history"], _good_site_state()["history"])
        self.assertEqual(state["meta"], {})

    def test_values_that_belong_together_stay_consistent(self):
        entry = _good_site_state()
        entry.update(status="down", down_since="yesterday", pending_recovery={"down_since": "x"})
        state = self._load({"version": 2, "meta": {"last_run": 777}, "sites": {"a": entry}})
        repaired = state["sites"]["a"]
        self.assertEqual(repaired["status"], "down")
        self.assertEqual(repaired["down_since"], 777)          # a DOWN site must have a start time
        self.assertIsNone(repaired["pending_recovery"])        # a recovery record needs both of its times

    def test_bad_history_rows_are_dropped_good_ones_kept(self):
        entry = _good_site_state()
        entry["history"] = [[1, 1, 5], "junk", [2, 9, 5], [3, 0, "slow"], [4, None, None]]
        state = self._load({"version": 2, "meta": {}, "sites": {"a": entry}})
        self.assertEqual(state["sites"]["a"]["history"], [[1, 1, 5], [4, None, None]])

    def test_a_repaired_state_does_not_crash_a_whole_run(self):
        server = FakeSites({"/": (200, {}, b"<html>hello</html>")})
        self.addCleanup(server.close)
        settings = make_settings()
        site = make_site(server.base + "/")
        bad = _good_site_state()
        bad.update(history="oops", down_since="yesterday", last_up_at="x")
        with open(settings.state_path, "w", encoding="utf-8") as handle:
            json.dump({"version": 2, "meta": {"last_run": time.time() - 600, "created": 1}, "sites": {site.site_id: bad}}, handle)
        stub = mock.Mock(name="email", accepts=lambda alert: True, send=lambda alerts: True)
        stub.name = "email"
        with mock.patch.object(main_module, "build_notifiers", lambda s: [stub]), contextlib.redirect_stdout(io.StringIO()):
            code = main_module.run_checks(settings, [site], dry_run=False)
        self.assertEqual(code, 0)
        saved = json.load(open(settings.state_path, encoding="utf-8"))
        self.assertEqual(saved["sites"][site.site_id]["last_state"], "UP")


class RecoveryOnlyForNotifiedOutagesTests(unittest.TestCase):
    def _down(self):
        return UptimeResult(signal=c.HTTP_ERROR, status_code=500, verdict=c.VERDICT_DOWN, attempts=3, error="HTTP 500", started_at=time.time())

    def _up(self):
        return UptimeResult(signal=c.OK, status_code=200, response_time=0.2, started_at=time.time())

    def test_recovered_follows_a_delivered_down(self):
        settings, site = make_settings(), make_site("http://127.0.0.1:9/")
        state = {"meta": {}, "sites": {}}
        site_state = state_store.get_site_state(state, site.site_id)
        down = evaluate_uptime(site, site_state, self._down(), 1000, settings)
        self.assertEqual([a.kind for a in down], ["DOWN"])
        apply_delivery(state, down[0], 1000)                       # the email really went out
        back = evaluate_uptime(site, site_state, self._up(), 2000, settings)
        self.assertEqual([a.kind for a in back], ["RECOVERED"])

    def test_no_recovered_when_the_down_email_never_got_through(self):
        settings, site = make_settings(), make_site("http://127.0.0.1:9/")
        state = {"meta": {}, "sites": {}}
        site_state = state_store.get_site_state(state, site.site_id)
        evaluate_uptime(site, site_state, self._down(), 1000, settings)   # alert created, never delivered
        back = evaluate_uptime(site, site_state, self._up(), 2000, settings)
        self.assertEqual(back, [])
        self.assertEqual(site_state["status"], "up")
        self.assertIsNone(site_state["pending_recovery"])


class CrashStepTests(unittest.TestCase):
    def test_crash_alert_does_not_write_a_stub_state(self):
        settings = make_settings()                      # no state file exists
        self.assertFalse(os.path.exists(settings.state_path))
        delivered = mock.Mock(delivered=[True])
        with mock.patch.object(main_module, "dispatch", lambda alerts, notifiers: delivered), \
                mock.patch.object(main_module, "build_notifiers", lambda s: [object()]), \
                mock.patch.object(main_module.heartbeat, "ping", lambda *a, **k: True):
            self.assertEqual(main_module.run_notify_crash(settings), 0)
        self.assertFalse(os.path.exists(settings.state_path), "a stub state would defeat the clean-start protection")

    def test_crash_alert_time_is_remembered_when_a_real_state_exists(self):
        settings = make_settings()
        state_store.save_state(settings.state_path, {"meta": {"last_run": 1}, "sites": {}})
        delivered = mock.Mock(delivered=[True])
        with mock.patch.object(main_module, "dispatch", lambda alerts, notifiers: delivered), \
                mock.patch.object(main_module, "build_notifiers", lambda s: [object()]), \
                mock.patch.object(main_module.heartbeat, "ping", lambda *a, **k: True):
            main_module.run_notify_crash(settings)
        self.assertIn("last_crash_alert", json.load(open(settings.state_path, encoding="utf-8"))["meta"])


class DnsAnswerTests(unittest.TestCase):
    def test_an_unreadable_dns_answer_is_a_lookup_error_not_a_crash(self):
        for payload in ([1, 2, 3], "text", 5, None):
            response = mock.Mock()
            response.json.return_value = payload
            with mock.patch.object(network.requests, "get", return_value=response):
                self.assertEqual(network._doh_query("https://resolver.test/q", "example.com", "A"), "ERROR", payload)


class ConfigGuardTests(unittest.TestCase):
    def test_a_url_with_an_impossible_port_is_skipped_with_a_message(self):
        settings = make_settings()          # (this clears SITES_JSON, so it must come first)
        os.environ["SITES_JSON"] = json.dumps([
            {"name": "Bad port", "url": "https://example.com:99999/"},
            {"name": "Fine", "url": "https://example.org/"},
        ])
        self.addCleanup(os.environ.pop, "SITES_JSON", None)
        report = load_sites_report(settings)
        self.assertEqual([s.name for s in report.sites], ["Fine"])
        self.assertEqual(report.skipped, 1)

    def test_numbers_must_be_finite_and_not_negative(self):
        for bad in ("nan", "inf", "-5", "-0.5"):
            os.environ["RETRY_GAP_SECONDS"] = bad
            try:
                with self.assertRaises(ConfigError, msg=bad):
                    load_settings()
            finally:
                os.environ.pop("RETRY_GAP_SECONDS", None)
        os.environ["RETRY_GAP_SECONDS"] = "0"
        try:
            self.assertEqual(load_settings().retry_gap_seconds, 0.0)
        finally:
            os.environ.pop("RETRY_GAP_SECONDS", None)


if __name__ == "__main__":
    unittest.main()
