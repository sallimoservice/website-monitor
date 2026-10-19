"""Small helpers for showing times in Pakistan time and durations in plain words."""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

TIMEZONE = ZoneInfo("Asia/Karachi")


def fmt_time(timestamp: float) -> str:
    """Format a Unix timestamp like '19 Oct 2026, 03:45 PM PKT'."""
    return datetime.fromtimestamp(timestamp, TIMEZONE).strftime("%d %b %Y, %I:%M %p PKT")


def fmt_duration(seconds: float) -> str:
    """Format a number of seconds like '1h 23m' or '2d 3h'."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"
