"""Guards so the saved-state fixtures cannot rot as the calendar moves. Run with:  python -m unittest discover -s tests"""

import re
import unittest
from pathlib import Path

VERIFICATION = Path(__file__).resolve().parent.parent / "verification"


class FixtureClockTests(unittest.TestCase):
    def test_every_suite_that_reads_the_old_state_ages_it_first(self):
        users = [p for p in VERIFICATION.glob("suite_*.py") if "state_old" in p.read_text(encoding="utf-8")]
        self.assertTrue(users, "expected at least the migration suites to use the old-format state")
        for path in users:
            text = path.read_text(encoding="utf-8")
            self.assertTrue("age_state" in text or "rejuvenate" in text, f"{path.name} uses the old state without aging it")

    def test_no_suite_hard_codes_a_real_looking_date(self):
        # 10-digit epoch seconds from 2023 onwards. The frozen-clock regression scenarios use a small, deliberate constant.
        pattern = re.compile(r"\b1[7-9]\d{8}\b")
        for path in VERIFICATION.glob("*.py"):
            if path.name == "regress_scenarios.py":
                continue
            self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")), f"{path.name} hard-codes a date")

    def test_age_state_puts_the_last_run_where_asked(self):
        import json
        import os
        import shutil
        import sys
        import time

        sys.path.insert(0, str(VERIFICATION))
        import _paths   # builds a throw-away work folder, fake certificate included

        self.addCleanup(lambda: shutil.rmtree(os.environ.pop("SP", _paths.SP), ignore_errors=True))

        state = json.loads((VERIFICATION / "fixtures" / "state_old_v1.json").read_text(encoding="utf-8"))
        aged = _paths.age_state(state, 3 * 86400)
        self.assertAlmostEqual(aged["meta"]["last_run"], time.time() - 3 * 86400, delta=5)
        oldest = min(row[0] for site in aged["sites"].values() for row in site["history"])
        self.assertLess(oldest, time.time())
        self.assertGreater(oldest, time.time() - 5 * 86400)


if __name__ == "__main__":
    unittest.main()
