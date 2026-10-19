"""Optional Healthchecks.io ping (the "dead man's switch").

After every successful run we visit your HEALTHCHECK_URL. If the pings stop
(GitHub paused the schedule, the repo was disabled, a long outage at GitHub),
Healthchecks.io emails you. It uses only the Python standard library.
"""

from __future__ import annotations

import logging
import urllib.request

log = logging.getLogger("monitor.heartbeat")


def ping(url: str) -> bool:
    if not url:
        return False
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "website-monitor"})
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read(100)
        log.info("Heartbeat ping sent.")
        return True
    except Exception as exc:  # a broken heartbeat must never break the monitor
        log.warning("Heartbeat ping failed (%s).", type(exc).__name__)
        return False
