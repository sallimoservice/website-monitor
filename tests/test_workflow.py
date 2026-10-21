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
