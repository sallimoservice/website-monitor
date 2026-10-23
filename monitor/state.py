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

from . import dryrun
from .checks.classify import SCANNABLE_SIGNALS

log = logging.getLogger("monitor.state")

# Version 2 only ADDS fields, so a saved version 1 file still loads (missing fields get defaults).
STATE_VERSION = 2
HISTORY_SECONDS = 25 * 3600  # keep a little over 24h of check results for the daily summary

DEFAULT_SITE_STATE = {
    "status": "unknown",        # unknown / up / down (the outage tracker)
    "last_state": "UNKNOWN",    # UP / SLOW / DOWN / WARNING / INSPECTION_BLOCKED / UNKNOWN as of the last run
    "last_up_at": None,         # last time the site gave a clean "up" answer
    "down_signal": None,        # what kind of failure started the outage (DNS_FAIL, CONN_FAIL ...)
    "down_inconclusive_since": None,  # outage still open, but only challenge/error pages seen since
    "inspection_blocked": False,      # last page could not be used for content checks
    "cloudflare_seen": False,   # a response ever came through Cloudflare (sticky)
    "tls_warn_active": False,   # a certificate warning is in effect
    "last_tls_alert": None,
    "text_missing_active": False,     # expected_text is confirmed missing
    "config_error_active": False,     # a site-side Cloudflare error (1016 ...) is confirmed
    "last_config_alert": None,
    "origin_trouble_active": False,   # errors or timeouts from the server behind Cloudflare, confirmed
    "last_origin_alert": None,
    "last_text_alert": None,
    "baseline_hash": None,      # content fingerprint of a CLEAN page (see store_baseline)
    "baseline_learned_at": None,
    "down_since": None,         # when the current outage was first seen
    "down_notified_at": None,   # when we last delivered a DOWN alert or reminder
    "pending_recovery": None,   # a RECOVERED alert that has not been delivered yet
    "slow_active": False,       # True while the site is slower than its limit
    "slow_alert_pending": False,  # a slow warning was raised but not delivered yet (retried next run)
    "last_slow_alert": None,    # when we last delivered a slow warning
    "refused_active": False,    # True while a "connection refused" warning is in effect
    "last_refused_alert": None, # when we last delivered a connection-refused warning
    "history": [],              # [[timestamp, 1 clean / 0 down / null unknown, response ms], ...]
}


def _fresh_state() -> dict:
    # "_fresh" lives only in memory for this run (it is never written to disk). It tells the
    # content checks that every baseline is being learned from scratch, so they must stay quiet.
    return {"version": STATE_VERSION, "meta": {"created": time.time()}, "sites": {}, "_fresh": True}


# Which fields hold what. Anything not listed in a set below, with a default of None, holds a timestamp.
_TEXT_OR_NONE = frozenset({"down_signal", "baseline_hash"})
_DICT_OR_NONE = frozenset({"pending_recovery"})
_META_NUMBERS = ("last_run", "created", "last_crash_alert", "state_rebuilt_at")


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _value_ok(key: str, default, value) -> bool:
    if isinstance(default, bool):
        return isinstance(value, bool)
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, list):
        return isinstance(value, list)
    if value is None:
        return True
    if key in _TEXT_OR_NONE:
        return isinstance(value, str)
    if key in _DICT_OR_NONE:
        return isinstance(value, dict)
    return _is_number(value)


def _history_row_ok(row) -> bool:
    return (
        isinstance(row, (list, tuple))
        and len(row) == 3
        and _is_number(row[0])
        and (row[1] is None or row[1] in (0, 1))
        and (row[2] is None or _is_number(row[2]))
    )


def repair_state(state: dict) -> int:
    """Replace values of the wrong type with their defaults. Returns how many were repaired.

    A hand-edited or half-written state.json used to crash every run (and the same bad file was
    saved again), which left every website unmonitored. Now a bad value is reset, a site entry that is
    not an object is dropped (that site starts as new), and everything else is kept.
    """
    repaired = 0
    if not isinstance(state.get("meta"), dict):
        state["meta"] = {}
        repaired += 1
    for key in _META_NUMBERS:
        if key in state["meta"] and not _is_number(state["meta"][key]):
            del state["meta"][key]
            repaired += 1
    for site_id in list(state["sites"]):
        entry = state["sites"][site_id]
        if not isinstance(entry, dict):
            del state["sites"][site_id]
            repaired += 1
            continue
        for key, default in DEFAULT_SITE_STATE.items():
            if key in entry and not _value_ok(key, default, entry[key]):
                entry[key] = copy.deepcopy(default)
                repaired += 1
        if isinstance(entry.get("history"), list):
            good = [list(row) for row in entry["history"] if _history_row_ok(row)]
            repaired += len(entry["history"]) - len(good)
            entry["history"] = good
        # Values that only make sense together. A repaired field must not leave a half-state behind.
        pending = entry.get("pending_recovery")
        if isinstance(pending, dict) and not (_is_number(pending.get("down_since")) and _is_number(pending.get("recovered_at"))):
            entry["pending_recovery"] = None
            repaired += 1
        if entry.get("status") == "down" and not _is_number(entry.get("down_since")):
            entry["down_since"] = state["meta"].get("last_run") or time.time()   # the best guess we have
            repaired += 1
    return repaired


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
        repaired = repair_state(state)
        if repaired:
            log.warning("Saved state had %d value(s) of the wrong type. They were reset, the rest was kept.", repaired)
        return state
    except (ValueError, OSError):
        log.warning("Saved state was unreadable, starting fresh.")
        return _fresh_state()


def save_state(path: str, state: dict) -> None:
    """Write state.json safely: write a temp file first, then swap it in."""
    dryrun.forbid("write the state file")
    state["version"] = STATE_VERSION
    state = {key: value for key, value in state.items() if key != "_fresh"}
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


def record_history(site_state: dict, now: float, ok, response_ms) -> None:
    """Remember this check result and drop anything older than ~25 hours.

    `ok` is True (clean answer), False (confirmed down) or None (unknown: the monitor got
    no usable page, so it can say nothing about the site).
    """
    history = site_state["history"]
    history.append([int(now), None if ok is None else (1 if ok else 0), response_ms])
    cutoff = now - HISTORY_SECONDS
    site_state["history"] = [row for row in history if row[0] >= cutoff]


def store_baseline(site_state: dict, result, fingerprint: str, now: float) -> bool:
    """The ONLY way to create or replace a content baseline.

    A baseline may only come from a clean, normal 200 page. A challenge, a Cloudflare
    block page or any error page is refused, and an existing baseline is left untouched.
    Returns True if the baseline was saved.
    """
    if result.signal not in SCANNABLE_SIGNALS or result.status_code != 200 or result.body is None:
        return False
    if not fingerprint:
        return False
    site_state["baseline_hash"] = fingerprint
    site_state["baseline_learned_at"] = now
    return True
