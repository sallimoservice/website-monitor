"""State storage in a plain state.json file (no database).

The file only holds hashed site IDs, statuses, timestamps and counters. It never
contains a URL or a client name, so it is safe to keep in the GitHub Actions cache
of a public repository.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import tempfile
import time
from pathlib import Path

log = logging.getLogger("monitor.state")

STATE_VERSION = 1
HISTORY_SECONDS = 25 * 3600  # keep a little over 24h of check results for the daily summary

DEFAULT_SITE_STATE = {
    "status": "unknown",        # unknown / up / down
    "down_since": None,         # when the current outage was first seen
    "down_notified_at": None,   # when we last delivered a DOWN alert or reminder
    "pending_recovery": None,   # a RECOVERED alert that has not been delivered yet
    "slow_active": False,       # True while the site is slower than its limit
    "last_slow_alert": None,    # when we last delivered a slow warning
    "history": [],              # [[timestamp, 1 or 0 (up), response ms], ...]
}


def _fresh_state() -> dict:
    return {"version": STATE_VERSION, "meta": {"created": time.time()}, "sites": {}}


def load_state(path: str) -> dict:
    """Load state.json. A missing or damaged file simply starts a fresh state."""
    state_file = Path(path)
    if not state_file.is_file():
        log.info("No saved state found, starting fresh.")
        return _fresh_state()
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or not isinstance(state.get("sites"), dict):
            raise ValueError("unexpected layout")
        state.setdefault("meta", {})
        return state
    except (ValueError, OSError):
        log.warning("Saved state was unreadable, starting fresh.")
        return _fresh_state()


def save_state(path: str, state: dict) -> None:
    """Write state.json safely: write a temp file first, then swap it in."""
    state["version"] = STATE_VERSION
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=target.parent or ".", prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=1, sort_keys=True)
        os.replace(tmp_name, target)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def get_site_state(state: dict, site_id: str) -> dict:
    """Return the state for one site, filling in any missing fields."""
    site_state = state["sites"].setdefault(site_id, {})
    for key, default in DEFAULT_SITE_STATE.items():
        site_state.setdefault(key, copy.deepcopy(default))
    return site_state


def prune_removed_sites(state: dict, active_ids) -> int:
    """Forget sites that are no longer in SITES_JSON. Returns how many were removed."""
    active = set(active_ids)
    stale = [site_id for site_id in state["sites"] if site_id not in active]
    for site_id in stale:
        del state["sites"][site_id]
    return len(stale)


def record_history(site_state: dict, now: float, ok: bool, response_ms) -> None:
    """Remember this check result and drop anything older than ~25 hours."""
    history = site_state["history"]
    history.append([int(now), 1 if ok else 0, response_ms])
    cutoff = now - HISTORY_SECONDS
    site_state["history"] = [row for row in history if row[0] >= cutoff]
