"""Independent confirmation, end to end through the real command line.

Fake websites, a fake Globalping, the fake mail server and a fake Healthchecks all listen on localhost, so this
shows what really lands in the mailbox. Only the runner's own address lookup is replaced (it would call the
internet), and DNS-over-HTTPS is replaced by the usual stand-in.
"""
import _paths
import email
import email.header
import glob
import json
import os
import re
import subprocess
import sys

for k in ("SITES_JSON", "SITES_FILE", "GITHUB_ACTIONS", "RETRY_GAP_SECONDS", "STAGGER_SECONDS", "HEALTHCHECK_URL", "GLOBALPING_TOKEN",
          "CONFIRM_ENABLED", "CONFIRM_WAIT_SECONDS", "DRY_RUN"):
    os.environ.pop(k, None)

import fake_healthchecks, fake_smtp
from tests.fake_globalping import FakeGlobalping, down, probes_for, reachable
from tests.helpers import FakeSites

SP, ROOT = _paths.SP, _paths.ROOT
fake_smtp.start(); fake_healthchecks.start()
HC = fake_healthchecks.paths
failures = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if detail and not cond else ""))
    if not cond: failures.append(label)

GOOD = (200, {}, b"<html><body>Welcome</body></html>")
BAD = (500, {}, b"server error")
IP = "203.0.113.7"
SMTP = dict(SMTP_HOST="localhost", SMTP_PORT="465", SMTP_USER="alerts@test.com", SMTP_PASSWORD="SuperSecret123",
            SMTP_FROM="alerts@test.com", EMAIL_TO="me@test.com")
CODE = (
    "import sys; from monitor.checks import network, confirm; "
    "network._doh_query = lambda url, host, rtype: 'NXDOMAIN' if host.endswith('.invalid') else 'OK'; "
    "confirm.lookup_runner_ip = lambda *a, **k: %r; "
    "import monitor.notifiers.email_smtp as e; e.RETRY_DELAY_SECONDS = 0; "
    "from monitor.main import main; sys.exit(main(%%r))" % IP
)


def mail_files():
    return sorted(glob.glob(f"{SP}/mail_migration/*.eml"))


def read_mail(path):
    msg = email.message_from_string(open(path, encoding="utf-8").read())
    subject = "".join(part.decode(enc or "utf-8") if isinstance(part, bytes) else part for part, enc in email.header.decode_header(msg["Subject"] or ""))
    body = []
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            body.append(part.get_payload(decode=True).decode("utf-8", "replace"))
    return subject, "\n".join(body)


class Lab:
    """Sites + Globalping for one scenario, and a way to run the monitor against them."""

    def __init__(self, routes, script=None, default=None, on_post=None, names=None):
        self.sites = FakeSites(routes)
        self.gp = FakeGlobalping(script=script, default=default, on_post=on_post)
        self.names = names or {path: f"Client {path.strip('/').upper()}" for path in routes}
        self.sites_file = os.path.join(SP, "confirm_sites.json")
        json.dump([{"name": name, "url": self.sites.base + path} for path, name in self.names.items()], open(self.sites_file, "w"))
        self.state = os.path.join(SP, f"confirm_state_{id(self)}.json")

    def close(self):
        self.sites.close(); self.gp.close()

    def run(self, args=(), **extra):
        env = dict(os.environ, SITES_FILE=self.sites_file, STATE_PATH=self.state, STATE_SALT="realsalt", RETRY_GAP_SECONDS="1",
                   TEXT_RECHECK_GAP_SECONDS="1", STAGGER_SECONDS="0", CONFIRM_WAIT_SECONDS="2", GLOBALPING_URL=self.gp.url,
                   NO_PROXY="*", no_proxy="*", SSL_CERT_FILE=f"{SP}/certs/cert.pem", HEALTHCHECK_URL="http://127.0.0.1:8084/hc",
                   LOG_REAL_NAMES="true", **SMTP)
        env.update(extra)
        for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            env.pop(k, None)
        HC.clear()
        before = len(mail_files())
        done = subprocess.run([sys.executable, "-c", CODE % (list(args),)], cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=300)
        mails = [read_mail(p) for p in mail_files()[before:]]
        if os.environ.get("SHOW_MAIL"):   # SHOW_MAIL=1 prints every email, to read the wording
            for subject, text in mails:
                print(f"----- EMAIL: {subject}\n{text}\n-----")
        return done.returncode, done.stdout + done.stderr, mails, list(HC)

    def seed(self):
        """One quiet first run with every site healthy, so the next run is not a fresh start."""
        good = {path: self.sites.routes[path] for path in self.sites.routes}
        for path in self.sites.routes:
            self.sites.routes[path] = GOOD
        rc, out, mails, hc = self.run()
        for path, route in good.items():
            self.sites.routes[path] = route
        return rc


print("== 1. the monitor is blocked, other locations load the site")
lab = Lab({"/a": BAD, "/b": GOOD, "/c": GOOD}, default=reachable()); lab.seed()
rc, out, mails, hc = lab.run()
subjects = [s for s, _ in mails]
print("  ", subjects, hc)
expect("no DOWN email", not any("DOWN" in s for s in subjects), subjects)
expect("one WARNING email", len(mails) == 1 and "WARNING" in subjects[0], subjects)
body = mails[0][1] if mails else ""
expect("it says the monitor may be blocked and names the site", "may be blocked" in body and "Client A" in body)
expect(f"it carries the runner IP ({IP}) and the Globalping measurement id", IP in body and "/v1/measurements/M0001" in body)
expect("it lists locations with city, country, network and result", "Frankfurt, DE" in body and "Hetzner Online GmbH" in body and "HTTP 200" in body)
expect("only the failing site went to Globalping (nothing for the two healthy ones)", set(lab.gp.paths()) == {"/a"}, lab.gp.paths())
expect("the run is green and the heartbeat is a success ping", rc == 0 and hc == ["/hc"], (rc, hc))
rc, out, mails, hc = lab.run()
expect("the next run, same situation: no second email (once a day)", mails == [], [s for s, _ in mails])
lab.close()

print("\n== 2. a real outage, confirmed in both rounds, then it comes back")
lab = Lab({"/a": BAD, "/b": GOOD}, default=down()); lab.seed()
rc, out, mails, hc = lab.run()
subjects = [s for s, _ in mails]
body = mails[0][1] if mails else ""
expect("exactly one DOWN email", len(mails) == 1 and "DOWN" in subjects[0], subjects)
expect("evidence of round 1 and round 2, with both measurement ids", "Round 1" in body and "Round 2" in body and "M0001" in body and "M0002" in body)
expect(f"evidence has the runner IP, locations, networks and the failure", IP in body and "Tokyo, JP" in body and "ECONNREFUSED" in body)
expect("two measurements for the failing site, none for the healthy one", lab.gp.paths() == ["/a", "/a"], lab.gp.paths())
expect("DOWN is stored", json.load(open(lab.state))["sites"] and any(v["status"] == "down" for v in json.load(open(lab.state))["sites"].values()))
lab.sites.routes["/a"] = GOOD
rc, out, mails, hc = lab.run()
expect("the next run, site loads: one back-online email", len(mails) == 1 and "RECOVERED" in mails[0][0], [s for s, _ in mails])
lab.close()

print("\n== 3. the confirmation service is broken, so nothing is called DOWN")
for label, scenario in (("HTTP 500", {"post_status": 500}), ("rate limited (429)", {"post_status": 429, "headers": {"X-RateLimit-Remaining": 0}}),
                        ("junk instead of JSON", {"junk": True, "probes": []}), ("fewer than 3 probes answer", {"probes": probes_for(500, 500, "offline", "offline", "offline")}),
                        ("a tie", {"probes": probes_for(500, 500, 200, 200)})):
    lab = Lab({"/a": BAD, "/b": GOOD}, default=scenario); lab.seed()
    rc, out, mails, hc = lab.run()
    subjects = [s for s, _ in mails]
    expect(f"{label}: one WARNING, no DOWN, run is green", len(mails) == 1 and "WARNING" in subjects[0] and "DOWN" not in subjects[0] and rc == 0, (subjects, rc))
    expect(f"{label}: the email says it could not confirm", "could not confirm" in (mails[0][1] if mails else ""))
    lab.close()

print("\n== 4. a short blip sends nothing")
lab = Lab({"/a": BAD, "/b": GOOD}, script={"/a": [down()]}, on_post=lambda path, n: lab.sites.routes.__setitem__("/a", GOOD))
lab.seed()
rc, out, mails, hc = lab.run()
expect("it failed once and the monitor loads it on the second look: no email at all", mails == [], [s for s, _ in mails])
expect("the second outside check was skipped", len(lab.gp.posts) == 1, len(lab.gp.posts))
lab.close()
lab = Lab({"/a": BAD, "/b": GOOD}, script={"/a": [down(), reachable()]}); lab.seed()
rc, out, mails, hc = lab.run()
expect("outside locations fail in round 1 and load it in round 2: no email", mails == [], [s for s, _ in mails])
lab.close()

print("\n== 5. many sites failing together: one summary, no DOWN")
paths = [f"/m{n}" for n in range(8)] + ["/ok1", "/ok2"]
lab = Lab({p: (BAD if p.startswith("/m") else GOOD) for p in paths}, default=down()); lab.seed()
rc, out, mails, hc = lab.run()
subjects = [s for s, _ in mails]
expect("one email, a WARNING, no DOWN", len(mails) == 1 and "WARNING" in subjects[0] and "DOWN" not in subjects[0], subjects)
expect("it names the failing sites and the runner IP", "Client M0" in mails[0][1] and "Client M7" in mails[0][1] and IP in mails[0][1])
expect("nothing was sent to Globalping", lab.gp.posts == [])
lab.close()

print("\n== 6. kill switch")
lab = Lab({"/a": BAD, "/b": GOOD}, default=reachable()); lab.seed()
rc, out, mails, hc = lab.run(CONFIRM_ENABLED="false")
expect("CONFIRM_ENABLED=false: DOWN from the runner alone, as before", len(mails) == 1 and "DOWN" in mails[0][0], [s for s, _ in mails])
expect("no request to Globalping", lab.gp.posts == [])
expect("the log says confirmation is off", "switched OFF" in out)
lab.close()

print("\n== 7. dry run")
lab = Lab({"/a": BAD, "/b": GOOD}, default=down()); lab.seed()
rc, out, mails, hc = lab.run(["--dry-run"])
expect("a dry run sends no email and no ping, and the outside check still runs", mails == [] and hc == [] and len(lab.gp.posts) == 2, (len(mails), hc, len(lab.gp.posts)))
expect("the report says what a real run would send", "confirmed DOWN" in out)
lab.close()

print("\n== 8. --test-confirm")
lab = Lab({"/a": GOOD}, default={"probes": probes_for(200, 200, 200, 500, 200)})
rc, out, mails, hc = lab.run(["--test-confirm"])
expect("prints the raw shape and the verdict, exit 0, no email, no ping", rc == 0 and "top-level keys" in out and "Verdict: up" in out and mails == [] and hc == [], (rc, hc))
expect("it asked about example.com, not one of the sites", lab.gp.posts[0]["target"] == "example.com")
lab.close()

print()
if failures:
    print(f"{len(failures)} FAILED")
    sys.exit(1)
