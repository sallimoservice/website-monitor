"""What happens to a damaged state file, through the real command line.

Some rows document a KNOWN GAP (see STAGE_B.md, item 2): a file whose contents have the wrong types makes
every run crash, and the same bad file is saved again. Those rows assert today's behaviour so that the day
the gap is fixed this suite fails and the expectation is updated on purpose.
"""
import glob
import json
import os
import sys

import _paths
import cf_server, fake_smtp

cf_server.start(); fake_smtp.start()
SP = os.environ["SP"]
failed = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else ""))
    if not cond: failed.append(label)

ENV = dict(os.environ, SITES_FILE=f"{SP}/hc_sites.json", STATE_SALT="realsalt", RETRY_GAP_SECONDS="1", STAGGER_SECONDS="0", NO_PROXY="*",
           SMTP_HOST="localhost", SMTP_PORT="465", SMTP_USER="a@t.com", SMTP_PASSWORD="x", EMAIL_TO="me@t.com",
           SSL_CERT_FILE=f"{SP}/certs/cert.pem", HEALTHCHECK_URL="")
seed_path = f"{SP}/audit/seed.json"
if os.path.exists(seed_path): os.remove(seed_path)
_paths.run_monitor([], dict(ENV, STATE_PATH=seed_path))
good = json.load(open(seed_path))
text = open(seed_path).read()

variants = {
    "truncated mid-file": (text[:300], "fresh", 0),
    "empty file": ("", "fresh", 0),
    "valid JSON, wrong shape (a list)": ("[1,2,3]", "fresh", 0),
    "valid JSON, sites is not a dict": (json.dumps({"version": 2, "meta": {}, "sites": []}), "fresh", 0),
    "binary garbage": ("\x00\x01\x02garbage", "fresh", 0),
    "unknown future version, same shape": (json.dumps({**good, "version": 9}), "loaded", 0),
    "meta missing entirely": (json.dumps({"version": 2, "sites": good["sites"]}), "loaded", 0),
    "KNOWN GAP site entry is a string": (json.dumps({**good, "sites": {k: "x" for k in good["sites"]}}), "crash", 1),
    "KNOWN GAP history is a string": (json.dumps({**good, "sites": {k: {**v, "history": "oops"} for k, v in good["sites"].items()}}), "crash", 1),
    "KNOWN GAP timestamps are strings": (json.dumps({**good, "sites": {k: {**v, "down_since": "yesterday", "down_notified_at": "x"} for k, v in good["sites"].items()}}), "crash", 1),
}
for label, (content, kind, code) in variants.items():
    path = f"{SP}/audit/state_x.json"
    with open(path, "w", errors="ignore") as handle:
        handle.write(content)
    before = len(glob.glob(f"{SP}/mail_migration/*.eml"))
    done = _paths.run_monitor([], dict(ENV, STATE_PATH=path))
    out = done.stdout + done.stderr
    seen = "fresh" if "STATE WAS MISSING" in out else ("crash" if "Traceback" in out else "loaded")
    mails = len(glob.glob(f"{SP}/mail_migration/*.eml")) - before
    expect(f"{label}: {seen}, exit {done.returncode}", seen == kind and done.returncode == code, f"expected {kind}/{code}")
    if seen == "fresh":
        expect(f"{label}: a fresh start sends no email", mails == 0, str(mails))
print("\nRESULT:", "ALL PASSED" if not failed else f"{len(failed)} FAILED -> {failed}")
sys.exit(1 if failed else 0)
