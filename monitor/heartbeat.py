"""Optional Healthchecks.io ping (the "dead man's switch").

After every successful run we visit your HEALTHCHECK_URL. If the pings stop
(GitHub paused the schedule, the repo was disabled, a long outage at GitHub),
Healthchecks.io emails you. It uses only the Python standard library.
"""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.request

from . import dryrun

log = logging.getLogger("monitor.heartbeat")

ATTEMPTS = 3
RETRY_DELAY_SECONDS = 3


def describe(url: str) -> str:
    """One line for the dry run. The URL itself is a secret and is never printed."""
    if not url:
        return "no heartbeat configured (HEALTHCHECK_URL is empty), so nobody is told if this monitor stops running"
    if not url.lower().startswith(("http://", "https://")):
        return "HEALTHCHECK_URL is set but is not a web address, so every ping would fail"
    return "configured (a dry run never pings it)"


def ping(url: str, failed: bool = False) -> bool:
    """Tell Healthchecks the run finished (or, with failed=True, that it did not work).

    Returns False when no URL is set or the ping could not be delivered. The caller decides what
    that means: a heartbeat that cannot be delivered must not look like a healthy run.
    """
    dryrun.forbid("ping Healthchecks")
    if not url:
        return False
    if failed:
        url = url.rstrip("/") + "/fail"
    for attempt in range(1, ATTEMPTS + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "website-monitor"})
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read(100)
            log.info("Heartbeat %s sent.", "failure signal" if failed else "ping")
            return True
        except urllib.error.HTTPError as exc:
            log.error("Heartbeat ping was refused (HTTP %s). Check HEALTHCHECK_URL.", exc.code)
            if exc.code < 500:
                return False   # a wrong address will not fix itself, so do not retry
        except Exception as exc:
            log.warning("Heartbeat ping attempt %d of %d failed (%s).", attempt, ATTEMPTS, type(exc).__name__)
        if attempt < ATTEMPTS:
            time.sleep(RETRY_DELAY_SECONDS)
    log.error("Heartbeat ping could not be delivered.")
    return False
