"""Checks on the workflow file itself. Run with:  python -m unittest discover -s tests"""

import re
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "monitor.yml"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _step(name: str) -> str:
    """The text of one workflow step, found by its name."""
    parts = re.split(r"(?m)^      - name: ", _text())
    for part in parts[1:]:
        if part.startswith(name):
            return part
    raise AssertionError(f"no step named {name!r}")


class ScheduleTests(unittest.TestCase):
    def test_cron_is_off_minute_zero(self):
        crons = re.findall(r'(?m)^\s*- cron:\s*"([^"]+)"', _text())
        self.assertEqual(crons, ["17 */8 * * *"])
        for cron in crons:
            self.assertNotEqual(cron.split()[0], "0", "GitHub delays and drops runs at the start of the hour")

    def test_manual_runs_are_still_possible(self):
        self.assertIn("workflow_dispatch:", _text())


if __name__ == "__main__":
    unittest.main()


class CacheTests(unittest.TestCase):
    def test_cache_cleanup_is_limited_to_this_branch(self):
        self.assertIn('--ref "$GITHUB_REF"', _step("Delete old state caches"))

    def test_cleanup_deletes_only_what_the_branch_scoped_list_returns(self):
        """Run the real cleanup command with a stand-in `gh` and look at what it was asked."""
        import os
        import stat
        import subprocess
        import tempfile

        block = re.search(r"(?m)^        run: \|\n((?:          .*\n?)+)", _step("Delete old state caches")).group(1)
        script = "\n".join(line[10:] for line in block.splitlines())
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "gh.log"
            fake = Path(tmp) / "gh"
            # `cache list` prints three ids (as if --jq had already dropped the newest 3); `cache delete` just records.
            fake.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\n[ "$2" = "list" ] && printf "11\\n12\\n"\nexit 0\n')
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            env = dict(os.environ, PATH=f"{tmp}:{os.environ['PATH']}", GITHUB_REF="refs/heads/main")
            subprocess.run(["sh", "-c", script], env=env, check=True)
            calls = log.read_text().splitlines()
        listing = [c for c in calls if c.startswith("cache list")]
        self.assertEqual(len(listing), 1)
        self.assertIn("--ref refs/heads/main", listing[0])
        self.assertEqual(sorted(c for c in calls if c.startswith("cache delete")), ["cache delete 11", "cache delete 12"])

    def test_dry_runs_and_test_alerts_never_save_or_delete(self):
        for name in ("Save state", "Delete old state caches"):
            step = _step(name)
            self.assertIn("inputs.dry_run != true", step, name)
            self.assertIn("inputs.test_alert != true", step, name)

    def test_dry_runs_may_read_the_cache(self):
        restore = _step("Restore saved state")
        self.assertIn("actions/cache/restore", restore)
        self.assertNotIn("inputs.dry_run", restore)
