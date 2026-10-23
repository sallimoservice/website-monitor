"""Shared test helpers: a local fake website and a way to build settings without a network."""

import dataclasses
import http.server
import os
import tempfile
import threading
import time

from monitor.config import Site, load_settings, make_site_id

CF = {"server": "cloudflare", "cf-ray": "8a1b2c3d4e5f6a7b-FRA"}


class FakeSites:
    """Local web server. `routes` maps a path to (status, extra headers, body)."""

    def __init__(self, routes):
        self.routes = routes
        self.hits = {}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.hits[self.path] = outer.hits.get(self.path, 0) + 1
                status, headers, body = outer.routes.get(self.path, (404, {}, b"missing"))
                if status == "hang":   # never answers within a test's read timeout
                    time.sleep(3)
                    status = 200
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def make_settings(**overrides):
    """Settings with no real network habits: no waits between visits, no stagger, temp state file."""
    for name in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS", "STAGGER_SECONDS", "HEALTHCHECK_URL",
                 "GLOBALPING_TOKEN", "GLOBALPING_URL", "CONFIRM_WAIT_SECONDS"):
        os.environ.pop(name, None)
    os.environ.update(
        STATE_SALT="test-salt", NO_PROXY="*", no_proxy="*", STATE_PATH=os.path.join(tempfile.mkdtemp(), "state.json"),
        SMTP_USER="alerts@example.com", SMTP_PASSWORD="x", EMAIL_TO="me@example.com",
        # The older tests are about the runner alone. Tests of the outside check switch it on themselves.
        CONFIRM_ENABLED="false",
    )
    settings = load_settings()
    base = dict(retry_gap_seconds=0.0, stagger_seconds=0.0, read_timeout=1.0, connect_timeout=1.0, text_recheck_gap_seconds=0.0)
    base.update(overrides)
    return dataclasses.replace(settings, **base)


def make_site(url, **kwargs):
    return Site(index=1, name="Test site", url=url, site_id=make_site_id("test-salt", url), expected_domain="example.com", **kwargs)
