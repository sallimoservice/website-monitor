"""Logging that never leaks secrets or client details.

GitHub Actions logs of a public repository are visible to everyone. Every line
we print passes through a scrubber that replaces known sensitive text (client
names, URLs, passwords, email addresses) with ***.
"""

from __future__ import annotations

import logging
import sys

# Text that must never appear in the logs. Filled in once the config is loaded.
_SCRUB_VALUES: list[str] = []


def register_sensitive(values) -> None:
    """Add text that must be hidden from every future log line."""
    for value in values:
        value = (value or "").strip()
        if len(value) >= 3 and value not in _SCRUB_VALUES:
            _SCRUB_VALUES.append(value)
    # Longest first, so "https://example.com" is hidden before "example.com".
    _SCRUB_VALUES.sort(key=len, reverse=True)


def scrub(text: str) -> str:
    """Replace every registered sensitive value in `text` with ***."""
    for value in _SCRUB_VALUES:
        text = text.replace(value, "***")
    return text


def mask_in_actions(values) -> None:
    """Ask GitHub Actions to hide these values everywhere in the run log."""
    for value in dict.fromkeys((v or "").strip() for v in values):  # skip duplicates
        if len(value) >= 3 and "\n" not in value and "\r" not in value:
            print(f"::add-mask::{value}", flush=True)


class _ScrubbingFormatter(logging.Formatter):
    """Formatter that scrubs the final text, including error tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return scrub(super().format(record))


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_ScrubbingFormatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    # Keep third-party libraries quiet (they may print full URLs).
    for noisy in ("urllib3", "requests"):
        logging.getLogger(noisy).setLevel(logging.ERROR)
