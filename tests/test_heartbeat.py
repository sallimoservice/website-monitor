"""Heartbeat behaviour. Run with:  python -m unittest discover -s tests"""

import http.server
import threading
import unittest

from monitor import heartbeat


class _Server:
    """A tiny local stand-in for Healthchecks. `status` is what it answers."""

    def __init__(self, status=200):
        self.paths = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                self.send_response(status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/ping/abc"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class PingTests(unittest.TestCase):
    def setUp(self):
        heartbeat.RETRY_DELAY_SECONDS = 0

    def test_success_and_fail_paths(self):
        server = _Server()
        self.addCleanup(server.close)
        self.assertTrue(heartbeat.ping(server.url))
        self.assertTrue(heartbeat.ping(server.url, failed=True))
        self.assertEqual(server.paths, ["/ping/abc", "/ping/abc/fail"])

    def test_dead_url_is_reported_as_failure(self):
        # Nothing listens here. The old code logged a warning and carried on as if all was well.
        self.assertFalse(heartbeat.ping("http://127.0.0.1:9/ping/abc"))

    def test_wrong_address_is_refused_not_retried(self):
        server = _Server(status=404)
        self.addCleanup(server.close)
        self.assertFalse(heartbeat.ping(server.url))
        self.assertEqual(len(server.paths), 1)

    def test_server_error_is_retried(self):
        server = _Server(status=503)
        self.addCleanup(server.close)
        self.assertFalse(heartbeat.ping(server.url))
        self.assertEqual(len(server.paths), heartbeat.ATTEMPTS)

    def test_no_url_is_not_a_success(self):
        self.assertFalse(heartbeat.ping(""))

    def test_describe_never_prints_the_url(self):
        text = heartbeat.describe("https://hc-ping.com/secret-uuid")
        self.assertNotIn("secret-uuid", text)
        self.assertIn("no heartbeat configured", heartbeat.describe(""))
        self.assertIn("not a web address", heartbeat.describe("hc-ping.com/abc"))


if __name__ == "__main__":
    unittest.main()


class RunExitTests(unittest.TestCase):
    """The whole run, with a stub email channel. A heartbeat that cannot be delivered fails the run."""

    def setUp(self):
        import contextlib
        import io
        from unittest import mock

        from monitor import main as main_module
        from tests.helpers import FakeSites, make_settings, make_site

        heartbeat.RETRY_DELAY_SECONDS = 0
        self.main = main_module
        self.contextlib, self.io = contextlib, io
        self.site_server = FakeSites({"/": (200, {}, b"<html><title>Fine</title><body>hello</body></html>")})
        self.addCleanup(self.site_server.close)
        self.make_settings = make_settings

        class Stub:
            name = "email"

            def accepts(self, alert):
                return True

            def send(self, alerts):
                return True

        patcher = mock.patch.object(main_module, "build_notifiers", lambda settings: [Stub()])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sites = [make_site(self.site_server.base + "/")]

    def _run(self, url, dry_run=False):
        import dataclasses

        settings = dataclasses.replace(self.make_settings(), healthcheck_url=url)
        out = self.io.StringIO()
        with self.contextlib.redirect_stdout(out):
            code = self.main.run_checks(settings, self.sites, dry_run=dry_run)
        return code, out.getvalue()

    def test_dead_url_fails_the_run(self):
        code, _ = self._run("http://127.0.0.1:9/ping/abc")
        self.assertEqual(code, 1)

    def test_good_url_passes_and_pings_once(self):
        server = _Server()
        self.addCleanup(server.close)
        code, _ = self._run(server.url)
        self.assertEqual(code, 0)
        self.assertEqual(server.paths, ["/ping/abc"])

    def test_no_url_is_a_pass_but_the_dry_run_says_so(self):
        code, _ = self._run("")
        self.assertEqual(code, 0)
        code, out = self._run("", dry_run=True)
        self.assertEqual(code, 0)
        self.assertIn("no heartbeat configured", out)

    def test_dry_run_never_pings(self):
        server = _Server()
        self.addCleanup(server.close)
        code, out = self._run(server.url, dry_run=True)
        self.assertEqual(code, 0)
        self.assertEqual(server.paths, [])
        self.assertIn("configured (a dry run never pings it)", out)
