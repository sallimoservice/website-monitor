"""Run every suite and print one count.   python verification/run_all.py

  --only NAME      run just the suites whose name contains NAME (for example --only round6)
  --allow-skips    exit 0 even if a suite had to be skipped (a skip is never counted as a pass)
  --keep           keep the throw-away work folder (fake certificates, mail, state files) to look at

Needs: Python 3.11 or newer, the openssl command, git history (for the Stage 1 comparison) and permission
to listen on localhost port 465 (root on Linux). A suite that cannot run says SKIPPED and why. Nothing here
touches the internet: the fake sites, mail server and Healthchecks all listen on localhost.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time

import _paths

SUITES = [
    ("stage_a", "Cloudflare-aware classification, retries, evidence, labels"),
    ("round2", "labels, per-site flags, history, dry-run table, email text"),
    ("round3", "Cloudflare 1xxx pages, DNS evidence, retry gap, settings help, dry runs and the cache"),
    ("round4", "stagger, rest between visits, load on healthy and failing sites"),
    ("round5", "Cloudflare overload, challenge look-alikes, shared hosting, masking"),
    ("round6", "email failure and heartbeat order, clean start, dry-run report and lock"),
    ("migration", "an old-format (version 1) state read by today's code, five scenarios"),
    ("regression", "15 scenarios against the frozen Stage 1 code, three approved differences"),
    ("refused_timeline", "connection_refused_is_warning over time"),
    ("request_rules", "the request itself and how plain answers are read"),
    ("corrupt_state", "damaged state files (includes documented known gaps)"),
    ("stale_state", "an 8-day-old state (includes documented known gaps)"),
    ("load_and_timing", "requests per site per run and the time a bad run takes"),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only")
    parser.add_argument("--allow-skips", action="store_true")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    env = dict(os.environ, SP=os.environ["SP"], STAGGER_SECONDS="0", PYTHONUNBUFFERED="1")
    rows, total_checks, started = [], 0, time.time()

    def record(name, what, status, count, seconds, tail=""):
        rows.append((name, what, status, count, seconds, tail))

    if not args.only or "unit" in args.only:
        t = time.time()
        done = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=str(_paths.ROOT), env=env, capture_output=True, text=True)
        ran = re.search(r"Ran (\d+) tests?", done.stderr)
        count = int(ran.group(1)) if ran else 0
        record("unit tests", "tests/ (heartbeat, 520, external sites, workflow file)", "PASS" if done.returncode == 0 else "FAIL", count, time.time() - t, done.stderr[-1500:])
    for name, what in SUITES:
        if args.only and args.only not in name:
            continue
        t = time.time()
        done = subprocess.run([sys.executable, os.path.join(str(_paths.HERE), f"suite_{name}.py")], cwd=str(_paths.ROOT), env=env, capture_output=True, text=True, timeout=1500)
        out = done.stdout + done.stderr
        count = len(re.findall(r"(?m)^PASS ", out))
        if done.returncode == 0:
            status = "PASS"
        elif done.returncode == _paths.SKIP_EXIT_CODE:
            status = "SKIPPED"
        else:
            status = "FAIL"
        tail = "\n".join(l for l in out.splitlines() if l.startswith(("FAIL", "SKIPPED", "Traceback")) or "Error" in l)[-1500:]
        record(f"suite_{name}", what, status, count, time.time() - t, tail)

    print(f"{'suite':22} {'result':8} {'checks':>6} {'secs':>5}  what it covers")
    for name, what, status, count, seconds, _ in rows:
        print(f"{name:22} {status:8} {count:>6} {seconds:5.0f}  {what}")
        total_checks += count if status == "PASS" else 0
    bad = [r for r in rows if r[2] == "FAIL"]
    skipped = [r for r in rows if r[2] == "SKIPPED"]
    for name, _, status, _, _, tail in bad + skipped:
        print(f"\n--- {name} {status}\n{tail}")
    print(f"\nTOTAL {total_checks} checks passed in {len([r for r in rows if r[2] == 'PASS'])} of {len(rows)} suites, "
          f"{len(bad)} failed, {len(skipped)} skipped, {time.time() - started:.0f}s")
    if not args.keep:
        shutil.rmtree(os.environ["SP"], ignore_errors=True)
    sys.exit(1 if bad or (skipped and not args.allow_skips) else 0)


if __name__ == "__main__":
    main()
