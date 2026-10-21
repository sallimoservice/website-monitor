"""Safety lock for --dry-run.

A dry run must never send an email, ping Healthchecks or write the state file. The three places
that could do those things call forbid() first, so if a future change ever lets a dry run reach
them, it stops with an error instead of quietly doing it.
"""

from __future__ import annotations

_armed = False


class DryRunViolation(RuntimeError):
    pass


def arm() -> None:
    global _armed
    _armed = True


def disarm() -> None:
    global _armed
    _armed = False


def forbid(action: str) -> None:
    if _armed:
        raise DryRunViolation(f"a dry run tried to {action}")
