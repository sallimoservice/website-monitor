"""Independent confirmation of DOWN. Everything here is offline: the sites and Globalping are local fakes.

The rule under test: a failure seen only from the GitHub runner never becomes DOWN. A site is DOWN only when
outside locations agree in two rounds. Run with:  python -m unittest discover -s tests
"""

import dataclasses
import time
import unittest
from unittest import mock

import requests

from monitor import main
from monitor.checks import classify as c
from monitor.checks import confirm
from monitor.checks.uptime import UptimeResult
from monitor.logic import evaluate_uptime
from monitor.notifiers import DispatchResult
from monitor.state import get_site_state, load_state, save_state
from tests.fake_globalping import FakeGlobalping, down, probe, probes_for, reachable
from tests.helpers import FakeSites, make_settings, make_site

RUNNER_IP = "203.0.113.7"
BAD = (500, {}, b"server error")
GOOD = (200, {}, b"<html>hello</html>")


def text_of(alert) -> str:
    return " | ".join([alert.summary] + [f"{label}: {value}" for label, value in alert.details])


class Harness(unittest.TestCase):
    """A fake website server, a fake Globalping and a way to run the whole monitor once against them."""

    def setUp(self):
        self.sites_server = None
        self.gp = None
        self.cleanups = []
        for patcher in (
            mock.patch.object(confirm, "POLL_SECONDS", 0.01),
            mock.patch.object(confirm, "lookup_runner_ip", lambda *a, **k: RUNNER_IP),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        for server in (self.sites_server, self.gp):
            if server:
                server.close()

    def start(self, routes, script=None, default=None, on_post=None, **settings_overrides):
        self.sites_server = FakeSites(routes)
        self.gp = FakeGlobalping(script=script, default=default, on_post=on_post)
        values = dict(confirm_enabled=True, confirm_wait_seconds=0.0, globalping_url=self.gp.url)
        values.update(settings_overrides)
        self.settings = dataclasses.replace(make_settings(), **values)

    def site(self, path="/", **kwargs):
        return make_site(self.sites_server.base + path, **kwargs)

    def seed(self, sites, **by_site):
        """Save a state that is not fresh (a fresh state holds every alert back). `by_site` maps path -> overrides."""
        state = {"meta": {"created": time.time() - 86400, "last_run": time.time() - 8 * 3600}, "sites": {}}
        for site in sites:
            entry = get_site_state(state, site.site_id)
            entry["status"] = "up"
            for path, values in by_site.items():
                if site.url.endswith(path):
                    entry.update(values)
        save_state(self.settings.state_path, state)

    def run_monitor(self, sites, seed=True, **by_site):
        if seed:
            self.seed(sites, **by_site)
        sent = []

        def fake_dispatch(alerts, notifiers):
            sent.extend(alerts)
            return DispatchResult(delivered=[True] * len(alerts), channels={"email": True})

        with mock.patch.object(main, "build_notifiers", return_value=[object()]), mock.patch.object(main, "dispatch", fake_dispatch):
            code = main.run_checks(self.settings, sites, dry_run=False)
        return code, sent, load_state(self.settings.state_path)

    def state_of(self, state, site):
        return state["sites"][site.site_id]


class ProbeJudgingTests(unittest.TestCase):
    def verdict(self, *outcomes):
        probes = [confirm.classify_probe(item) for item in probes_for(*outcomes)]
        return confirm.judge(probes)[0]

    def test_no_answer_5xx_404_and_410_fail_a_probe(self):
        for outcome in ("connect ECONNREFUSED", 500, 502, 503, 404, 410):
            self.assertEqual(confirm.classify_probe(probes_for(outcome)[0]).outcome, confirm.PROBE_FAILING, outcome)

    def test_any_page_that_answers_counts_as_reachable(self):
        for code in (200, 301, 302, 401, 403, 429):
            self.assertEqual(confirm.classify_probe(probes_for(code)[0]).outcome, confirm.PROBE_REACHABLE, code)

    def test_offline_probes_are_left_out(self):
        self.assertEqual(confirm.classify_probe(probes_for("offline")[0]).outcome, confirm.PROBE_NO_ANSWER)
        # three failing probes and two offline ones: the verdict is judged on the three that answered
        self.assertEqual(self.verdict(500, 500, 500, "offline", "offline"), confirm.VERDICT_DOWN)

    def test_fewer_than_three_answering_probes_is_unclear(self):
        self.assertEqual(self.verdict(500, 500, "offline", "offline", "offline"), confirm.VERDICT_UNCLEAR)
        self.assertEqual(self.verdict(200, 200, "offline", "offline", "offline"), confirm.VERDICT_UNCLEAR)

    def test_a_tie_is_unclear(self):
        self.assertEqual(self.verdict(500, 500, 200, 200, "offline"), confirm.VERDICT_UNCLEAR)

    def test_a_majority_decides(self):
        self.assertEqual(self.verdict(500, 500, 500, 200, 200), confirm.VERDICT_DOWN)
        self.assertEqual(self.verdict(500, 500, 200, 200, 200), confirm.VERDICT_UP)

    def test_junk_in_a_result_is_no_answer(self):
        for junk in (None, "text", 5, [], {}, {"probe": {}, "result": {"status": "finished", "statusCode": "200"}},
                     {"probe": {}, "result": {"status": "finished", "statusCode": True}}):
            self.assertEqual(confirm.classify_probe(junk).outcome, confirm.PROBE_NO_ANSWER, repr(junk))


class OutsideCheckFailsTests(Harness):
    """The confirmation service itself is broken. That must be a warning, never a DOWN."""

    def check_unconfirmed(self, scenario, expect_text):
        self.start({"/": BAD}, script={"/": [scenario]})
        site = self.site()
        code, sent, state = self.run_monitor([site])
        self.assertEqual([a.kind for a in sent], ["WARNING"], [text_of(a) for a in sent])
        self.assertEqual(sent[0].tag, "unconfirmed")
        self.assertIn("NOT reported as down", sent[0].summary)
        self.assertIn(expect_text, text_of(sent[0]))
        entry = self.state_of(state, site)
        self.assertNotEqual(entry["status"], "down")
        self.assertEqual(entry["last_state"], "WARNING")
        self.assertIsNone(entry["down_notified_at"])
        self.assertEqual(code, 0)

    def test_server_error_500(self):
        self.check_unconfirmed({"post_status": 500}, "HTTP 500")

    def test_rate_limited_429(self):
        self.check_unconfirmed({"post_status": 429, "headers": {"X-RateLimit-Remaining": 0, "X-RateLimit-Reset": 1800}},
                               "free limit is used up")

    def test_a_result_that_is_not_json(self):
        self.check_unconfirmed({"junk": True, "probes": []}, "unreadable")

    def test_the_post_answer_is_not_json(self):
        self.check_unconfirmed({"post_status": 202, "post_body": b"<html>oops</html>"}, "unreadable")

    def test_the_post_answer_has_no_id(self):
        self.check_unconfirmed({"post_status": 202, "post_body": {"nothing": 1}}, "unreadable")

    def test_a_measurement_that_never_finishes(self):
        with mock.patch.object(confirm, "EXTRA_WAIT_SECONDS", 0.3), mock.patch.object(confirm, "DEFAULT_PROBE_TIMEOUT", 0):
            self.check_unconfirmed({"never_finishes": True, "probes": []}, "did not finish in time")

    def test_a_result_that_cannot_be_read_back(self):
        self.check_unconfirmed({"get_status": 500, "probes": []}, "could not return the result")

    def test_a_network_timeout_reaching_globalping(self):
        self.start({"/": BAD})
        with mock.patch.object(confirm.requests, "post", side_effect=requests.ConnectTimeout("slow")):
            code, sent, state = self.run_monitor([self.site()])
        self.assertEqual([a.kind for a in sent], ["WARNING"])
        self.assertIn("could not reach Globalping", text_of(sent[0]))

    def test_a_finished_measurement_with_no_results(self):
        self.check_unconfirmed({"probes": []}, "only 0 of 0")

    def test_the_outside_check_crashing_is_never_a_down(self):
        self.start({"/": BAD})
        site = self.site()
        with mock.patch.object(confirm, "run_confirmation", side_effect=RuntimeError("boom")):
            code, sent, state = self.run_monitor([site])
        self.assertEqual([a.kind for a in sent], ["WARNING"])
        self.assertEqual(sent[0].tag, "unconfirmed")
        self.assertNotEqual(self.state_of(state, site)["status"], "down")
        self.assertEqual(code, 1, "a crash must stay visible: the run fails and Healthchecks hears /fail")


class RunnerBlockedTests(Harness):
    def test_runner_blocked_while_other_locations_succeed_is_not_down(self):
        self.start({"/": BAD}, script={"/": [reachable()]})
        site = self.site()
        code, sent, state = self.run_monitor([site])
        self.assertEqual([(a.kind, a.tag) for a in sent], [("WARNING", "blocked")])
        alert = sent[0]
        self.assertIn("may be blocked", alert.summary)
        self.assertIn("NOT reported as down", alert.summary)
        entry = self.state_of(state, site)
        self.assertEqual((entry["status"], entry["last_state"]), ("up", "WARNING"))
        self.assertIsNone(entry["down_since"])
        self.assertEqual(len(self.gp.posts), 1, "no second round, nothing to wait for")
        self.assertEqual(code, 0)

    def test_the_warning_carries_the_evidence(self):
        self.start({"/": BAD}, script={"/": [{"probes": probes_for(200, 200, 200, 200, 200)}]})
        code, sent, state = self.run_monitor([self.site()])
        body = text_of(sent[0])
        self.assertIn(f"Checked from IP: {RUNNER_IP}", body)
        self.assertIn("Frankfurt, DE", body)
        self.assertIn("Hetzner Online GmbH (AS24940)", body)
        self.assertIn("HTTP 200", body)
        self.assertIn("/v1/measurements/M0001", body)          # the Globalping measurement
        self.assertRegex(body, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC")

    def test_the_warning_is_sent_at_most_once_a_day(self):
        self.start({"/": BAD}, script={"/": [reachable()]})
        site = self.site()
        _, first, _ = self.run_monitor([site])
        _, second, state = self.run_monitor([site], seed=False)
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [], "the next run, 8 hours later in real life, must not repeat it")
        entry = self.state_of(state, site)
        entry["last_blocked_alert"] -= 25 * 3600
        save_state(self.settings.state_path, state)
        _, third, _ = self.run_monitor([site], seed=False)
        self.assertEqual([a.tag for a in third], ["blocked"], "a day later it is mentioned again")

    def test_a_blocked_site_that_later_loads_sends_no_back_online(self):
        self.start({"/": BAD}, script={"/": [reachable()]})
        site = self.site()
        self.run_monitor([site])
        self.sites_server.routes["/"] = GOOD
        _, sent, state = self.run_monitor([site], seed=False)
        self.assertEqual(sent, [])
        self.assertEqual(self.state_of(state, site)["last_state"], "UP")
        self.assertIsNone(self.state_of(state, site)["pending_recovery"])


class ConfirmedDownTests(Harness):
    def test_a_real_outage_confirmed_in_both_rounds_is_down(self):
        self.start({"/": BAD}, script={"/": [down(), down()]})
        site = self.site()
        code, sent, state = self.run_monitor([site])
        self.assertEqual([(a.kind, a.tag) for a in sent], [("DOWN", "down")])
        entry = self.state_of(state, site)
        self.assertEqual(entry["status"], "down")
        self.assertIsNotNone(entry["down_notified_at"])
        self.assertEqual(len(self.gp.posts), 2, "round 1 and round 2")

    def test_the_down_alert_carries_the_evidence_of_both_rounds(self):
        self.start({"/": BAD}, script={"/": [down(), down()]})
        _, sent, _ = self.run_monitor([self.site()])
        body = text_of(sent[0])
        self.assertIn(f"Checked from IP: {RUNNER_IP}", body)
        for city in ("Frankfurt, DE", "Ashburn, US", "Tokyo, JP"):
            self.assertIn(city, body)
        self.assertIn("connect ECONNREFUSED", body)
        self.assertIn("Round 1", body)
        self.assertIn("Round 2", body)
        self.assertIn("/v1/measurements/M0001", body)
        self.assertIn("/v1/measurements/M0002", body)
        self.assertEqual(len(__import__("re").findall(r"Round \d, Globalping: [^|]*\(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC", body)), 2)
        self.assertIn("Other locations around the world could not load it either", sent[0].summary)

    def test_the_wait_between_the_rounds_comes_from_the_settings(self):
        self.start({"/": BAD}, script={"/": [down(), down()]})
        waits = []
        site = self.site()
        results = {site.site_id: self.runner_result(site)}
        source = confirm.GlobalpingSource(base_url=self.gp.url, sleep=lambda s: None)
        settings = dataclasses.replace(self.settings, confirm_wait_seconds=300.0)
        run = confirm.run_confirmation([site], results, settings, [source], sleep=waits.append, ip_lookup=lambda: RUNNER_IP,
                                       recheck=lambda sites: {s.site_id: self.runner_result(s) for s in sites})
        self.assertEqual(waits, [300.0])
        self.assertEqual(run.outcomes[site.site_id].outcome, confirm.OUTCOME_CONFIRMED_DOWN)

    def runner_result(self, site):
        from monitor.checks.uptime import run_uptime_checks
        return run_uptime_checks([site], self.settings)[site.site_id]

    def test_a_short_blip_where_the_runner_recovers_sends_nothing(self):
        flip = lambda host, seen: self.sites_server.routes.__setitem__("/", GOOD) if seen == 1 else None
        self.start({"/": BAD}, script={"/": [down()]}, on_post=flip)
        site = self.site()
        code, sent, state = self.run_monitor([site])
        self.assertEqual(sent, [])
        entry = self.state_of(state, site)
        self.assertEqual((entry["status"], entry["last_state"]), ("up", "UP"))
        self.assertEqual(len(self.gp.posts), 1, "the second outside check is skipped once the runner loads the site")

    def test_a_short_blip_where_the_outside_clears_sends_nothing(self):
        self.start({"/": BAD}, script={"/": [down(), reachable()]})
        site = self.site()
        code, sent, state = self.run_monitor([site])
        self.assertEqual(sent, [])
        self.assertNotEqual(self.state_of(state, site)["status"], "down")
        self.assertEqual(len(self.gp.posts), 2)

    def test_round_two_that_cannot_be_read_is_a_warning_not_a_down(self):
        self.start({"/": BAD}, script={"/": [down(), {"post_status": 500}]})
        code, sent, state = self.run_monitor([self.site()])
        self.assertEqual([(a.kind, a.tag) for a in sent], [("WARNING", "unconfirmed")])

    def test_a_tie_in_round_one_is_a_warning(self):
        self.start({"/": BAD}, script={"/": [{"probes": probes_for(500, 500, 200, 200, "offline")}]})
        code, sent, state = self.run_monitor([self.site()])
        self.assertEqual([(a.kind, a.tag) for a in sent], [("WARNING", "unconfirmed")])
        self.assertIn("split", text_of(sent[0]))

    def test_fewer_than_three_answering_probes_is_a_warning(self):
        self.start({"/": BAD}, script={"/": [{"probes": probes_for(500, 500, "offline", "offline", "offline")}]})
        code, sent, state = self.run_monitor([self.site()])
        self.assertEqual([(a.kind, a.tag) for a in sent], [("WARNING", "unconfirmed")])
        self.assertIn("only 2 of 5", text_of(sent[0]))

    def test_offline_probes_do_not_count_for_or_against(self):
        probes = probes_for(500, 500, 500, "offline", "offline")
        self.start({"/": BAD}, script={"/": [{"probes": probes}, {"probes": probes}]})
        code, sent, state = self.run_monitor([self.site()])
        self.assertEqual([a.kind for a in sent], ["DOWN"])


class BackOnlineTests(Harness):
    def test_back_online_follows_a_confirmed_and_announced_down(self):
        self.start({"/": BAD}, script={"/": [down(), down()]})
        site = self.site()
        _, first, _ = self.run_monitor([site])
        self.assertEqual([a.kind for a in first], ["DOWN"])
        self.sites_server.routes["/"] = GOOD
        _, second, state = self.run_monitor([site], seed=False)
        self.assertEqual([a.kind for a in second], ["RECOVERED"])
        self.assertEqual(self.state_of(state, site)["status"], "up")

    def test_no_warning_path_ever_sets_the_down_state(self):
        scenarios = {
            "blocked": reachable(),
            "unconfirmed": {"post_status": 500},
            "tie": {"probes": probes_for(500, 500, 200, 200)},
        }
        for name, scenario in scenarios.items():
            with self.subTest(name):
                self.start({"/": BAD}, script={"/": [scenario]})
                site = self.site()
                _, sent, state = self.run_monitor([site])
                self.assertNotIn("DOWN", [a.kind for a in sent])
                entry = self.state_of(state, site)
                self.assertEqual((entry["status"], entry["down_since"], entry["down_notified_at"]), ("up", None, None))
                self.sites_server.routes["/"] = GOOD
                _, later, _ = self.run_monitor([site], seed=False)
                self.assertNotIn("RECOVERED", [a.kind for a in later])
                self.tearDown()

    def test_an_old_outage_is_closed_when_other_locations_load_the_site(self):
        self.start({"/": BAD}, script={"/": [reachable()]})
        site = self.site()
        down_state = dict(status="down", down_since=time.time() - 3600, down_notified_at=time.time() - 3600,
                          down_signal=c.HTTP_ERROR, last_up_at=time.time() - 9 * 3600)
        _, sent, state = self.run_monitor([site], **{"/": down_state})
        self.assertEqual(sorted(a.kind for a in sent), ["RECOVERED", "WARNING"])
        recovered = next(a for a in sent if a.kind == "RECOVERED")
        self.assertIn("Other locations around the world can load it again", text_of(recovered))
        self.assertEqual(self.state_of(state, site)["status"], "up")


class AlreadyDownTests(Harness):
    """Sites that were confirmed DOWN earlier (like the one with the 8 hour reminders) keep their reminders."""

    def down_state(self, hours_since_notice):
        return {"/": dict(status="down", down_since=time.time() - 30 * 3600, down_notified_at=time.time() - hours_since_notice * 3600,
                          down_signal=c.HTTP_ERROR, last_up_at=time.time() - 40 * 3600)}

    def test_the_reminder_is_kept_when_the_outage_is_confirmed_again(self):
        self.start({"/": BAD}, script={"/": [down()]})
        site = self.site()
        _, sent, state = self.run_monitor([site], **self.down_state(9))
        self.assertEqual([(a.kind, a.label) for a in sent], [("DOWN", "STILL DOWN")])
        self.assertEqual(len(self.gp.posts), 1, "one outside check, and no waiting for an old outage")
        self.assertIn("Frankfurt, DE", text_of(sent[0]))
        self.assertEqual(self.state_of(state, site)["status"], "down")

    def test_no_reminder_before_it_is_due(self):
        self.start({"/": BAD}, script={"/": [down()]})
        _, sent, _ = self.run_monitor([self.site()], **self.down_state(2))
        self.assertEqual(sent, [])

    def test_a_reminder_is_not_sent_when_the_outside_check_cannot_confirm(self):
        self.start({"/": BAD}, script={"/": [{"post_status": 429}]})
        site = self.site()
        _, sent, state = self.run_monitor([site], **self.down_state(9))
        self.assertEqual([(a.kind, a.tag) for a in sent], [("WARNING", "unconfirmed")])
        self.assertEqual(self.state_of(state, site)["status"], "down", "the outage stays open")


class SafetyTests(Harness):
    def test_the_kill_switch_restores_runner_only_alerts_and_makes_no_outside_request(self):
        self.start({"/": BAD}, confirm_enabled=False)
        _, sent, _ = self.run_monitor([self.site()])
        self.assertEqual([a.kind for a in sent], ["DOWN"])
        self.assertEqual(self.gp.posts, [])

    def test_the_kill_switch_comes_from_the_environment(self):
        import os
        from monitor.config import load_settings
        make_settings()
        for value, expected in (("false", False), ("0", False), ("no", False), ("", True), ("true", True)):
            with mock.patch.dict(os.environ, {"CONFIRM_ENABLED": value}):
                self.assertIs(load_settings().confirm_enabled, expected, value)

    def test_a_mass_failure_sends_one_warning_and_no_down(self):
        paths = [f"/m{n}" for n in range(8)]
        self.start({path: BAD for path in paths}, default=down())
        sites = [self.site(path) for path in paths]
        sites = [dataclasses.replace(s, index=i + 1) for i, s in enumerate(sites)]
        code, sent, state = self.run_monitor(sites)
        self.assertEqual([(a.kind, a.tag) for a in sent], [("WARNING", "massfail")])
        self.assertEqual(self.gp.posts, [], "nothing is sent to Globalping when this many sites fail together")
        body = text_of(sent[0])
        self.assertIn("8 sites", body)
        self.assertIn(f"Checked from IP: {RUNNER_IP}", body)
        for site in sites:
            self.assertNotEqual(self.state_of(state, site)["status"], "down")
            self.assertEqual(self.state_of(state, site)["last_state"], "UNKNOWN")

    def test_seven_failures_are_not_a_mass_failure(self):
        paths = [f"/m{n}" for n in range(7)]
        self.start({path: BAD for path in paths}, default=down())
        sites = [dataclasses.replace(self.site(path), index=i + 1) for i, path in enumerate(paths)]
        _, sent, _ = self.run_monitor(sites)
        self.assertNotIn("massfail", [a.tag for a in sent])

    def test_at_most_five_sites_are_sent_out_per_run(self):
        paths = [f"/s{n}" for n in range(7)]
        self.start({path: BAD for path in paths}, default=down())
        sites = [dataclasses.replace(self.site(path), index=i + 1) for i, path in enumerate(paths)]
        _, sent, state = self.run_monitor(sites)
        self.assertEqual(len(set(self.gp.paths())), 5)
        self.assertEqual(len(self.gp.posts), 10, "5 sites, 2 rounds each")
        kinds = sorted((a.kind, a.tag) for a in sent)
        self.assertEqual(kinds, [("DOWN", "down")] * 5 + [("WARNING", "unconfirmed")] * 2)
        skipped = [a for a in sent if a.tag == "unconfirmed"]
        self.assertIn("at most 5 sites", text_of(skipped[0]))

    def test_only_failing_sites_are_sent_to_globalping(self):
        self.start({"/up": GOOD, "/also-up": GOOD, "/bad": BAD, "/slow-but-ok": GOOD}, default=reachable())
        sites = [dataclasses.replace(self.site(p), index=i + 1) for i, p in enumerate(["/up", "/also-up", "/bad", "/slow-but-ok"])]
        self.run_monitor(sites)
        self.assertEqual(set(self.gp.paths()), {"/bad"})

    def test_no_query_string_or_secret_leaves_the_machine(self):
        self.start({"/page": BAD}, default=reachable())
        site = self.site("/page", read_timeout_seconds=None)
        site = dataclasses.replace(site, url=site.url + "?token=SECRET123&user=bob")
        self.run_monitor([site])
        import json
        sent_out = json.dumps(self.gp.posts)
        self.assertNotIn("SECRET123", sent_out)
        self.assertNotIn("token", sent_out)
        self.assertNotIn("bob", sent_out)
        self.assertNotIn("alerts@example.com", sent_out)
        self.assertNotIn("test-salt", sent_out)
        self.assertEqual(self.gp.posts[0]["measurementOptions"]["request"]["path"], "/page")

    def test_it_works_without_a_token_and_uses_one_when_given(self):
        self.start({"/": BAD}, default=reachable())
        self.run_monitor([self.site()])
        self.assertEqual(set(self.gp.auth), {None}, "no token, no Authorization header")
        self.settings = dataclasses.replace(self.settings, globalping_token="free-token-value")
        self.run_monitor([self.site()], seed=False)
        self.assertIn("Bearer free-token-value", self.gp.auth)

    def test_the_token_is_masked_in_logs(self):
        self.assertIn("free-token-value", dataclasses.replace(make_settings(), globalping_token="free-token-value").sensitive_values())

    def test_a_dns_failure_needs_no_outside_check(self):
        site = make_site("http://127.0.0.1:9/")
        result = UptimeResult(signal=c.DNS_FAIL, verdict=c.VERDICT_DOWN, attempts=3, strict=False)
        self.assertFalse(confirm.is_candidate(site, result, False))
        settings = dataclasses.replace(make_settings(), confirm_enabled=True)
        state = {"meta": {}, "sites": {}}
        alerts = evaluate_uptime(site, get_site_state(state, site.site_id), result, time.time(), settings)
        self.assertEqual([a.kind for a in alerts], ["DOWN"])

    def test_a_would_be_down_without_any_outside_answer_is_a_warning(self):
        site = make_site("http://127.0.0.1:9/")
        result = UptimeResult(signal=c.CONN_FAIL, verdict=c.VERDICT_DOWN, attempts=3, strict=False)
        settings = dataclasses.replace(make_settings(), confirm_enabled=True)
        state = {"meta": {}, "sites": {}}
        entry = get_site_state(state, site.site_id)
        alerts = evaluate_uptime(site, entry, result, time.time(), settings)
        self.assertEqual([(a.kind, a.tag) for a in alerts], [("WARNING", "unconfirmed")])
        self.assertEqual(entry["status"], "unknown")

    def test_dry_run_still_checks_from_outside_and_sends_nothing(self):
        self.start({"/": BAD}, script={"/": [down(), down()]})
        site = self.site()
        self.seed([site])
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main.run_checks(self.settings, [site], dry_run=True)
        self.assertEqual(code, 0)
        self.assertEqual(len(self.gp.posts), 2)
        self.assertIn("confirmed DOWN", out.getvalue())
        self.assertEqual(load_state(self.settings.state_path)["sites"][site.site_id]["status"], "up", "a dry run saves nothing")


class TestConfirmCommandTests(Harness):
    def test_it_prints_the_shape_of_the_answer_and_reads_it(self):
        self.start({}, default={"probes": probes_for(200, 200, 200, 500, 200)})
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main.run_test_confirm(self.settings, "example.com")
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("example.com", text)
        self.assertIn("top-level keys", text)
        self.assertIn("statusCode", text)
        self.assertIn("Verdict: up", text)
        self.assertIn(RUNNER_IP, text)
        self.assertEqual(self.gp.posts[0]["target"], "example.com")

    def test_it_fails_loudly_when_globalping_does(self):
        self.start({}, default={"post_status": 429})
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main.run_test_confirm(self.settings, "example.com")
        self.assertEqual(code, 1)
        self.assertIn("did NOT work", out.getvalue())


class PluggableSourceTests(Harness):
    """Another free source can be added by writing one class. The decision logic does not change."""

    class Stub(confirm.ConfirmationSource):
        def __init__(self, name, verdicts):
            self.name = name
            self.verdicts = list(verdicts)
            self.asked = 0

        def check(self, site, runner_result):
            self.asked += 1
            verdict = self.verdicts[min(self.asked, len(self.verdicts)) - 1]
            probes = [confirm.ProbeResult("Somewhere, XX", "Some Network (AS1)", "eyeball", confirm.PROBE_FAILING, "HTTP 503")]
            return confirm.Confirmation(source=self.name, ok=verdict != confirm.VERDICT_UNCLEAR, verdict=verdict,
                                        reason=f"{self.name} says {verdict}", probes=probes, started_at=time.time())

    def decide(self, sources):
        self.start({"/": BAD})
        site = self.site()
        from monitor.checks.uptime import run_uptime_checks
        results = run_uptime_checks([site], self.settings)
        run = confirm.run_confirmation([site], results, self.settings, sources, ip_lookup=lambda: RUNNER_IP,
                                       recheck=lambda sites: run_uptime_checks(sites, self.settings))
        return run.outcomes[site.site_id]

    def test_a_different_source_drives_the_same_decision(self):
        stub = self.Stub("Other source", [confirm.VERDICT_DOWN])
        outcome = self.decide([stub])
        self.assertEqual(outcome.outcome, confirm.OUTCOME_CONFIRMED_DOWN)
        self.assertEqual(stub.asked, 2, "round 1 and round 2")
        rows = dict(confirm.evidence_rows(outcome))
        self.assertIn("Round 1, Other source", rows)

    def test_the_next_source_is_asked_only_when_the_first_is_unclear(self):
        first, second = self.Stub("First", [confirm.VERDICT_UNCLEAR]), self.Stub("Second", [confirm.VERDICT_UP])
        outcome = self.decide([first, second])
        self.assertEqual((first.asked, second.asked), (1, 1))
        self.assertEqual(outcome.outcome, confirm.OUTCOME_RUNNER_BLOCKED)
        spare = self.Stub("Spare", [confirm.VERDICT_DOWN])
        self.decide([self.Stub("Clear", [confirm.VERDICT_UP]), spare])
        self.assertEqual(spare.asked, 0)

    def test_a_source_that_raises_is_unclear_not_a_crash_and_not_a_down(self):
        class Broken(confirm.ConfirmationSource):
            name = "Broken"

            def check(self, site, runner_result):
                raise RuntimeError("boom")

        self.assertEqual(self.decide([Broken()]).outcome, confirm.OUTCOME_UNCONFIRMED)

    def test_no_source_at_all_is_unclear(self):
        self.assertEqual(self.decide([]).outcome, confirm.OUTCOME_UNCONFIRMED)


class StateFieldTests(unittest.TestCase):
    def test_new_fields_have_defaults_and_wrong_types_are_repaired(self):
        from monitor.state import repair_state
        state = {"meta": {}, "sites": {}}
        entry = get_site_state(state, "abc")
        for key in ("blocked_active", "unconfirmed_active"):
            self.assertIs(entry[key], False)
        for key in ("last_blocked_alert", "last_unconfirmed_alert"):
            self.assertIsNone(entry[key])
        entry.update(blocked_active="yes", last_unconfirmed_alert="yesterday")
        self.assertEqual(repair_state(state), 2)
        self.assertIs(entry["blocked_active"], False)
        self.assertIsNone(entry["last_unconfirmed_alert"])


if __name__ == "__main__":
    unittest.main()
