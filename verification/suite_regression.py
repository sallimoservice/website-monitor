"""Run the same 15 scenarios through the frozen Stage 1 code and through today's code, and compare.

Stage 1 (commit 6a5c558, the last Stage 1 state on main) is rebuilt from git history, so no old code is
stored in the repository. Exactly three scenarios may differ, all approved on purpose:
  HTTP 500            the DOWN reminder moved from 6 hours to 8 hours
  certificate invalid DOWN became a WARNING
  recovered           the recovery text says "up to N hours (checked every 8 hours)"
Anything else that differs is a regression.
"""
import json
import os
import subprocess
import sys
import tempfile

import _paths

STAGE_1_COMMIT = "6a5c558"
APPROVED_DIFFERENCES = {"HTTP 500", "certificate invalid", "recovered (500 then OK)"}


def rebuild_stage_1(folder):
    try:
        archive = subprocess.run(["git", "archive", STAGE_1_COMMIT], cwd=str(_paths.ROOT), capture_output=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        _paths.skip(f"commit {STAGE_1_COMMIT} is not in this checkout (a shallow clone?). Run: git fetch --unshallow")
    subprocess.run(["tar", "-x", "-C", folder], input=archive, check=True)


def scenarios(code_root):
    env = dict(os.environ, PYTHONPATH=code_root, VERIFY_USE_PYTHONPATH="1", STAGGER_SECONDS="0", NO_PROXY="*")
    done = subprocess.run([sys.executable, os.path.join(str(_paths.HERE), "regress_scenarios.py")], cwd=code_root, env=env,
                          capture_output=True, text=True, timeout=600)
    if done.returncode != 0:
        print(done.stdout[-1500:], done.stderr[-1500:])
        raise SystemExit(f"scenario run failed for {code_root}")
    return json.loads(done.stdout.strip().splitlines()[-1])


failed = []
def expect(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (f"   [{detail}]" if (detail and not cond) else ""))
    if not cond: failed.append(label)


with tempfile.TemporaryDirectory() as old_tree:
    rebuild_stage_1(old_tree)
    old = scenarios(old_tree)
new = scenarios(str(_paths.ROOT))

expect("same scenarios on both sides", set(old) == set(new) and len(old) == 15, f"{len(old)} / {len(new)}")
for name in old:
    if name not in APPROVED_DIFFERENCES:
        expect(f"{name}: identical to Stage 1", old[name] == new[name], f"old {old[name]} new {new[name]}")
differing = {name for name in old if old[name] != new[name]}
expect("only the approved scenarios differ", differing == APPROVED_DIFFERENCES, str(sorted(differing ^ APPROVED_DIFFERENCES)))
expect("HTTP 500: Stage 1 reminded after 7h, now first reminder at 9h (8 hour rule)",
       [r[0] for r in old["HTTP 500"] if r[1] == ["DOWN-reminder"]] == [25200] and [r[0] for r in new["HTTP 500"] if r[1] == ["DOWN-reminder"]] == [32400])
expect("certificate invalid: DOWN became WARNING", old["certificate invalid"][0][1] == ["DOWN"] and new["certificate invalid"][0][1] == ["WARNING"])
expect("recovery: still exactly one RECOVERED alert, now with the 'up to' wording",
       old["recovered (500 then OK)"][-1][1] == new["recovered (500 then OK)"][-1][1] == ["RECOVERED"]
       and new["recovered (500 then OK)"][-1][2][0].startswith("up to"))
print("\nRESULT:", "ALL PASSED" if not failed else f"{len(failed)} FAILED -> {failed}")
sys.exit(1 if failed else 0)
