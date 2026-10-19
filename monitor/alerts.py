"""The Alert object that checks create and notifiers send."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

DOWN = "DOWN"
RECOVERED = "RECOVERED"
SECURITY = "SECURITY"
WARNING = "WARNING"
CRASH = "CRASH"
INFO = "INFO"
TEST = "TEST"

EMOJI = {
    DOWN: "🔴",
    RECOVERED: "✅",
    SECURITY: "🚨",
    WARNING: "⚠️",
    CRASH: "🚨",
    INFO: "ℹ️",
    TEST: "🧪",
}

# Most serious first. Used to choose the emoji for a grouped email.
SEVERITY_ORDER = [CRASH, SECURITY, DOWN, WARNING, RECOVERED, INFO, TEST]

# These get the "high priority" flag on email.
HIGH_PRIORITY_KINDS = {DOWN, SECURITY, CRASH}


@dataclass
class Alert:
    kind: str                      # one of the constants above
    site_name: str                 # real client name (shown in email and WhatsApp only)
    url: str
    summary: str                   # one clear sentence about what happened
    details: list = field(default_factory=list)   # [(label, value), ...]
    ts: float = 0.0                # when it happened (Unix time)
    tag: str = ""                  # lets the engine mark the alert as delivered
    site_id: str = ""
    headline: str = ""             # optional label replacing the kind, e.g. "STILL DOWN"

    @property
    def emoji(self) -> str:
        return EMOJI.get(self.kind, "ℹ️")

    @property
    def label(self) -> str:
        return self.headline or self.kind

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or "" if self.url else ""

    @property
    def high_priority(self) -> bool:
        return self.kind in HIGH_PRIORITY_KINDS


def top_kind(alerts) -> str:
    """The most serious kind present in a group of alerts."""
    kinds = {a.kind for a in alerts}
    for kind in SEVERITY_ORDER:
        if kind in kinds:
            return kind
    return INFO


def group_summary(alerts) -> str:
    """Short text like '3 DOWN, 1 RECOVERED' for a grouped subject line."""
    counts = {}
    for alert in alerts:
        counts[alert.kind] = counts.get(alert.kind, 0) + 1
    ordered = [k for k in SEVERITY_ORDER if k in counts]
    return ", ".join(f"{counts[k]} {k}" for k in ordered)
