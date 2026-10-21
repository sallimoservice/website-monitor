"""A state file that is 8 days old (a long gap, or a branch dry run that kept the cache alive).

Aged with _paths.age_state, so the fixture is always "8 days ago" however old the file itself is.
Asserts there is no email burst: one grouped email, one reminder per still-down site. It also records a
KNOWN GAP (STAGE_B.md, item 3): the text after a gap counts time the monitor was not running.
"""
import email
import glob
import json
import os
import sys
import time
from email import policy

import _paths
import cf_server, fake_smtp

cf_server.start(); fake_smtp.start()
SP = os.environ["SP"]
failed = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else ""))
    if not cond: failed.append(label)

import hashlib, hmac
IDS = {}
for entry in json.load(open(f"{SP}/sites17.json")):
    IDS[entry["name"]] = hmac.new(b"realsalt", entry["url"].strip().lower().rstrip("/").encode(), hashlib.sha256).hexdigest()[:16]
OLD = json.load(open(f"{SP}/mig/state_old.json"))
EIGHT_DAYS = 8 * 86400


def run(label, mutate):
    state = _paths.age_state(json.loads(json.dumps(OLD)), EIGHT_DAYS)
    mutate(state)
    path = f"{SP}/audit/state_{label}.json"
    json.dump(state, open(path, "w"))
    json.dump({"03": "slow"}, open(f"{SP}/dyn_modes.json", "w"))
    before = len(glob.glob(f"{SP}/mail_migration/*.eml"))
    env = dict(os.environ, SITES_FILE=f"{SP}/sites17.json", STATE_PATH=path, STATE_SALT="realsalt", RETRY_GAP_SECONDS="1", TEXT_RECHECK_GAP_SECONDS="1",
               STAGGER_SECONDS="0", NO_PROXY="*", SMTP_HOST="localhost", SMTP_PORT="465", SMTP_USER="alerts@test.com", SMTP_PASSWORD="x",
               SMTP_FROM="alerts@test.com", EMAIL_TO="me@test.com", SSL_CERT_FILE=f"{SP}/certs/cert.pem")
    done = _paths.run_monitor([], env)
    files = sorted(glob.glob(f"{SP}/mail_migration/*.eml"))[before:]
    heads, body = [], ""
    for name in files:
        msg = email.message_from_string(open(name, encoding="utf-8").read(), policy=policy.default)
        body += msg.get_body(preferencelist=("plain",)).get_content()
    for block in body.split("-" * 40):
        lines = [l for l in block.strip().splitlines() if l.strip()]
        if lines:
            heads.append(lines[0])
    return done.returncode, len(files), heads, body


rc, mails, heads, body = run("a", lambda s: None)
expect("A. still down after 8 days: exit 0, one email, one reminder", rc == 0 and mails == 1 and heads == ["🔴 STILL DOWN - Limo 17"], f"{rc} {mails} {heads}")
expect("A. KNOWN GAP: the text counts the gap ('Down for' 190+ hours)", "Down for: 19" in body or "Down for: 2" in body, body[:300])

def pending(state):
    now = time.time()
    state["sites"][IDS["Limo 05"]]["pending_recovery"] = {"down_since": now - EIGHT_DAYS - 3600, "recovered_at": now - EIGHT_DAYS, "last_up_at": now - EIGHT_DAYS - 7200}
rc, mails, heads, body = run("b", pending)
expect("B. an undelivered recovery from 8 days ago: one email, recovery plus one reminder", rc == 0 and mails == 1 and sorted(heads) == ["✅ RECOVERED - Limo 05", "🔴 STILL DOWN - Limo 17"], f"{heads}")

def down_then_up(state):
    now = time.time()
    state["sites"][IDS["Limo 14"]].update(status="down", down_since=now - EIGHT_DAYS - 600, down_notified_at=now - EIGHT_DAYS, down_signal="CF_ORIGIN_ERROR", last_up_at=now - EIGHT_DAYS - 30000)
rc, mails, heads, body = run("c", down_then_up)
expect("C. down 8 days ago, up now: one email, one recovery, no storm", rc == 0 and mails == 1 and sorted(heads) == ["✅ RECOVERED - Limo 14", "🔴 STILL DOWN - Limo 17"], f"{heads}")
expect("C. KNOWN GAP: 'Downtime up to 2xx hours' counts time nobody was watching", "up to 20" in body or "up to 19" in body, body[:400])
print("\nRESULT:", "ALL PASSED" if not failed else f"{len(failed)} FAILED -> {failed}")
sys.exit(1 if failed else 0)
