"""A stand-in for the Globalping API, for offline tests. It speaks only the two calls the monitor makes:

    POST /v1/measurements          start a measurement   -> 202 {"id": ...}
    GET  /v1/measurements/{id}     read the result

What a site gets back is scripted: `script[path]` is a list of scenarios, one per measurement started for the site
with that URL path (the last one repeats). The test sites all live on 127.0.0.1, so the path tells them apart. Every request is recorded in `posts`, so a test can see exactly what was sent.
"""

import http.server
import json
import threading

_COUNTRY = {"Frankfurt": "DE", "Paris": "FR", "Ashburn": "US", "Dallas": "US", "Tokyo": "JP", "Sydney": "AU"}


def probe(city="Frankfurt", code=200, fail=None, offline=False, network="Hetzner Online GmbH", asn=24940, tags=None, ms=210):
    """One probe's entry in a Globalping result list (the shape the OpenAPI spec describes)."""
    where = {"continent": "EU", "country": _COUNTRY.get(city, "XX"), "city": city, "asn": asn, "network": network,
             "tags": ["datacenter-network"] if tags is None else tags}
    if offline:
        result = {"status": "failed", "failureSource": "internal", "rawOutput": "probe went offline"}
    elif fail:
        result = {"status": "failed", "failureSource": "target", "rawOutput": fail}
    else:
        result = {"status": "finished", "statusCode": code, "headers": {}, "rawBody": "", "timings": {"total": ms}}
    return {"probe": where, "result": result}


CITIES = ["Frankfurt", "Paris", "Ashburn", "Dallas", "Tokyo"]


def probes_for(*outcomes):
    """probes_for(200, 200, 500, "refused", "offline") -> one probe per outcome, spread over cities."""
    items = []
    for city, outcome in zip(CITIES, outcomes):
        if outcome == "offline":
            items.append(probe(city, offline=True))
        elif isinstance(outcome, str):
            items.append(probe(city, fail=outcome))
        else:
            items.append(probe(city, code=outcome))
    return items


def reachable(count=5):
    return {"probes": probes_for(*([200] * count))}


def down(count=5):
    return {"probes": probes_for(*(["connect ECONNREFUSED"] * count))}


class FakeGlobalping:
    def __init__(self, script=None, default=None, on_post=None):
        self.script = script or {}
        self.default = default or reachable()
        self.on_post = on_post
        self.posts = []          # the JSON body of every measurement that was started
        self.auth = []           # the Authorization header of every start request (None when none was sent)
        self.gets = 0
        self.measurements = {}
        self.polls_before_done = 1
        self.rate_remaining = 250
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body, headers=None):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for key, value in (headers or {}).items():
                    self.send_header(key, str(value))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                outer.posts.append(body)
                outer.auth.append(self.headers.get("Authorization"))
                host = outer.key(body)
                seen = sum(1 for post in outer.posts if outer.key(post) == host)
                scenarios = outer.script.get(host)
                scenario = outer.default
                if scenarios:
                    scenario = scenarios[min(seen, len(scenarios)) - 1]
                if outer.on_post:
                    outer.on_post(host, seen)
                if scenario.get("post_status"):
                    return self._send(scenario["post_status"], scenario.get("post_body", {"error": {"type": "x"}}),
                                      scenario.get("headers"))
                measurement_id = f"M{len(outer.posts):04d}"
                outer.measurements[measurement_id] = {"scenario": scenario, "polls": 0, "host": host}
                outer.rate_remaining -= len(scenario.get("probes", [])) or 5
                self._send(202, {"id": measurement_id, "probesCount": 5},
                           {"X-RateLimit-Limit": 250, "X-RateLimit-Remaining": outer.rate_remaining, "X-RateLimit-Reset": 3000})

            def do_GET(self):
                outer.gets += 1
                measurement = outer.measurements.get(self.path.rsplit("/", 1)[-1])
                if measurement is None:
                    return self._send(404, {"error": {"type": "not_found"}})
                scenario = measurement["scenario"]
                measurement["polls"] += 1
                if scenario.get("get_status"):
                    return self._send(scenario["get_status"], scenario.get("get_body", {}))
                if scenario.get("junk"):
                    return self._send(200, b"<html>not json</html>")
                if scenario.get("never_finishes") or measurement["polls"] <= outer.polls_before_done:
                    return self._send(200, {"id": self.path.rsplit("/", 1)[-1], "status": "in-progress", "results": []})
                self._send(200, {"id": self.path.rsplit("/", 1)[-1], "type": "http", "status": "finished",
                                 "target": measurement["host"], "probesCount": len(scenario["probes"]),
                                 "results": scenario["probes"]})

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1"

    @staticmethod
    def key(body):
        return ((body.get("measurementOptions") or {}).get("request") or {}).get("path")

    def paths(self):
        """The URL path of every measurement that was started: which sites were sent out."""
        return [self.key(post) for post in self.posts]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
