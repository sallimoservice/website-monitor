"""Optional Healthchecks.io ping (the "dead man's switch").

After every successful run we visit your HEALTHCHECK_URL. If the pings stop
(GitHub paused the schedule, the repo was disabled, a long outage at GitHub),
Healthchecks.io emails you. It uses only the Python standard library.
"""

from __future__ import annotations

import logging
import urllib.request

from . import dryrun

log = logging.getLogger("monitor.heartbeat")


def ping(url: str, failed: bool = False) -> bool:
    """Tell Healthchecks the run finished (or, with failed=True, that it did not work)."""
    dryrun.forbid("ping Healthchecks")
    if not url:
        return False
    if failed:
        url = url.rstrip("/") + "/fail"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "website-monitor"})
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read(100)
        log.info("Heartbeat %s sent.", "failure signal" if failed else "ping")
        return True
    except Exception as exc:  # a broken heartbeat must never break the monitor
        log.warning("Heartbeat ping failed (%s).", type(exc).__name__)
        return False
