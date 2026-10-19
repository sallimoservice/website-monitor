"""Notification channels. Each channel works on its own, so one failing never blocks another."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .email_smtp import EmailNotifier

log = logging.getLogger("monitor.notify")


@dataclass
class DispatchResult:
    delivered: list = field(default_factory=list)   # one True/False per alert
    channels: dict = field(default_factory=dict)    # {"email": True, ...}


def build_notifiers(settings) -> list:
    """Only channels that are fully configured are switched on. Others are skipped silently."""
    notifiers = []
    if settings.email_enabled:
        notifiers.append(EmailNotifier(settings))
    return notifiers


def dispatch(alerts, notifiers) -> DispatchResult:
    """Send alerts through every channel. An alert counts as delivered if ANY channel took it."""
    result = DispatchResult(delivered=[False] * len(alerts))
    for notifier in notifiers:
        indexes = [i for i, alert in enumerate(alerts) if notifier.accepts(alert)]
        if not indexes:
            continue
        try:
            ok = bool(notifier.send([alerts[i] for i in indexes]))
        except Exception:
            log.exception("%s notifier crashed", notifier.name)
            ok = False
        result.channels[notifier.name] = ok
        if ok:
            for i in indexes:
                result.delivered[i] = True
        else:
            log.error("%s delivery failed.", notifier.name.capitalize())
    return result
