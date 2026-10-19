"""Decides when to alert. Turns check results into alerts without ever spamming.

Rules
- ONE "DOWN" alert when a site goes down, a reminder every 6 hours while it stays down.
- ONE "RECOVERED" alert (with the downtime) when it comes back.
- A "slow" warning when the response time passes the limit, at most once per hour.
- If an alert could not be delivered by any channel, it is tried again on the next run.
"""

from __future__ import annotations

from .alerts import DOWN, INFO, RECOVERED, WARNING, Alert
from .state import record_history
from .timeutil import fmt_duration, fmt_time

SLOW_WARNING_COOLDOWN_SECONDS = 3600


def evaluate_uptime(site, site_state: dict, result, now: float, settings) -> list:
    """Update one site's state from a check result and return the alerts to send."""
    alerts = []
    response_ms = round(result.response_time * 1000) if result.response_time is not None else None
    record_history(site_state, now, result.ok, response_ms)

    if not result.ok:
        if site_state["status"] != "down":
            site_state.update(
                status="down",
                down_since=now,
                down_notified_at=None,
                pending_recovery=None,
                slow_active=False,
            )
        last = site_state["down_notified_at"]
        reminder_seconds = settings.down_reminder_hours * 3600
        if last is None:
            alerts.append(_down_alert(site, site_state, result, now, reminder=False))
        elif now - last >= reminder_seconds:
            alerts.append(_down_alert(site, site_state, result, now, reminder=True))
        return alerts

    # The site answered correctly.
    if site_state["status"] == "down":
        site_state["pending_recovery"] = {"down_since": site_state["down_since"], "recovered_at": now}
        site_state["down_since"] = None
        site_state["down_notified_at"] = None
    site_state["status"] = "up"

    if site_state["pending_recovery"]:
        alerts.append(_recovered_alert(site, site_state, result, now))

    alerts.extend(_slow_alerts(site, site_state, result, now))
    return alerts


def _slow_alerts(site, site_state, result, now) -> list:
    slow = result.response_time is not None and result.response_time > site.slow_threshold_seconds
    if not slow:
        site_state["slow_active"] = False
        return []
    already_slow = site_state["slow_active"]
    site_state["slow_active"] = True
    if already_slow:
        return []  # one warning per slow period, not one every 5 minutes
    last = site_state["last_slow_alert"]
    if last is not None and now - last < SLOW_WARNING_COOLDOWN_SECONDS:
        return []
    return [
        Alert(
            kind=WARNING,
            site_name=site.name,
            url=site.url,
            summary=f"Slow response ({result.response_time:.1f}s, limit is {site.slow_threshold_seconds:g}s)",
            details=[("Response time", f"{result.response_time:.2f}s"), ("HTTP status", str(result.status_code))],
            ts=now,
            tag="slow",
            site_id=site.site_id,
        )
    ]


def _down_alert(site, site_state, result, now, reminder: bool) -> Alert:
    details = []
    if result.status_code:
        details.append(("HTTP status", str(result.status_code)))
    details.append(("Checks", f"All {result.attempts} attempts failed"))
    details.append(("Down since", fmt_time(site_state["down_since"])))
    if reminder:
        details.append(("Down for", fmt_duration(now - site_state["down_since"])))
    return Alert(
        kind=DOWN,
        site_name=site.name,
        url=site.url,
        summary=result.error or "Website is not responding",
        details=details,
        ts=now,
        tag="down",
        site_id=site.site_id,
        headline="STILL DOWN" if reminder else "",
    )


def _recovered_alert(site, site_state, result, now) -> Alert:
    pending = site_state["pending_recovery"]
    details = [
        ("Downtime", fmt_duration(pending["recovered_at"] - pending["down_since"])),
        ("Down since", fmt_time(pending["down_since"])),
    ]
    if result.status_code:
        details.append(("HTTP status", str(result.status_code)))
    if result.response_time is not None:
        details.append(("Response time", f"{result.response_time:.2f}s"))
    return Alert(
        kind=RECOVERED,
        site_name=site.name,
        url=site.url,
        summary="Website is back online",
        details=details,
        ts=now,
        tag="recovered",
        site_id=site.site_id,
    )


def started_alert(site_count: int, now: float) -> Alert:
    """Sent once, the first time the monitor runs with a fresh state."""
    return Alert(
        kind=INFO,
        site_name="Website Monitor",
        url="",
        summary=f"Monitoring is active for {site_count} website(s).",
        details=[("Checks", "Every 5 minutes, you only get alerts when something changes")],
        ts=now,
        tag="started",
    )


def apply_delivery(state: dict, alert: Alert, now: float) -> None:
    """Record that an alert was really delivered. Undelivered alerts are retried next run."""
    if alert.tag == "started":
        state["meta"]["started_notified"] = now
        return
    site_state = state["sites"].get(alert.site_id)
    if site_state is None:
        return
    if alert.tag == "down":
        site_state["down_notified_at"] = now
    elif alert.tag == "recovered":
        site_state["pending_recovery"] = None
    elif alert.tag == "slow":
        site_state["last_slow_alert"] = now
