"""Decides when to alert. Turns check results into alerts without ever spamming.

Rules
- ONE "DOWN" alert when a site goes down, a reminder every 8 hours while it stays down.
- ONE "RECOVERED" alert ("down for up to X hours") when it comes back.
- A site is DOWN only when 3 visits at least 60 seconds apart agree (see checks/classify.py).
- Cloudflare challenge and block pages are never DOWN and never send anything. They only
  switch content checks off for that site (inspection_blocked).
- A "slow" warning when the response time passes the limit, at most once per hour.
- Sites with "connection_refused_is_warning" get a WARNING (not DOWN) when the connection
  is refused: once, then a reminder every 24 hours while it keeps happening.
- An invalid or expired certificate is a WARNING (never DOWN) on sites not behind Cloudflare.
- A missing expected_text on a normal page is a WARNING.
- A Cloudflare 1xxx page about the SITE (1016 origin DNS error and similar) is never DOWN, but
  becomes a WARNING once 3 visits in a row show it. 1xxx pages about the VISITOR (1020, 1015 ...)
  stay silent.

Labels are separate from alerts. A site only gets the label UP when the monitor received a clean
normal page. A 403 or 503 answer, a missing response or a challenge page never earns UP, even
when (as always) no alert is sent for it.
- If an alert could not be delivered by any channel, it is tried again on the next run.
"""

from __future__ import annotations

import math

from .alerts import DOWN, RECOVERED, WARNING, Alert
from .checks import classify as c
from .state import record_history
from .timeutil import fmt_time, fmt_utc

SLOW_WARNING_COOLDOWN_SECONDS = 3600
REFUSED_REMINDER_SECONDS = 24 * 3600
WARNING_REMINDER_SECONDS = 24 * 3600
DNS_OR_CONNECTION = (c.DNS_FAIL, c.CONN_FAIL)


def evaluate_uptime(site, site_state: dict, result, now: float, settings) -> list:
    """Update one site's state from a check result and return the alerts to send."""
    response_ms = round(result.response_time * 1000) if result.response_time is not None else None
    if result.cloudflare:
        site_state["cloudflare_seen"] = True

    if result.verdict == c.VERDICT_MIXED:
        # Three trustworthy failures of different kinds. Say nothing, look again next run.
        record_history(site_state, now, None, response_ms)
        site_state["last_state"] = "DOWN" if site_state["status"] == "down" else "UNKNOWN"
        return []
    if not result.config_confirmed:
        site_state["config_error_active"] = False

    is_down = result.verdict == c.VERDICT_DOWN
    # A site that is already DOWN stays in the normal DOWN flow. Timeouts, DNS errors,
    # SSL errors and HTTP errors are never downgraded, only refused connections.
    refused_as_warning = (
        is_down
        and result.signal == c.CONN_FAIL
        and site.connection_refused_is_warning
        and site_state["status"] != "down"
    )
    # History: 1 = clean page, 0 = confirmed down, None = unknown (no usable page either way).
    if is_down and not refused_as_warning:
        history_flag = False
    elif result.signal == c.OK:
        history_flag = True
    else:
        history_flag = None
    record_history(site_state, now, history_flag, response_ms)

    if refused_as_warning:
        site_state["inspection_blocked"] = False
        alerts = _refused_warning(site, site_state, result, now, settings)
    else:
        site_state["refused_active"] = False
        if is_down:
            alerts = _handle_down(site, site_state, result, now, settings)
        else:
            alerts = _handle_not_down(site, site_state, result, now, settings)
    site_state["last_state"] = _final_state(site_state, result)
    return alerts


def _final_state(site_state: dict, result) -> str:
    if site_state["status"] == "down":
        return "DOWN"
    if (
        site_state["refused_active"]
        or site_state["tls_warn_active"]
        or site_state["text_missing_active"]
        or site_state["config_error_active"]
    ):
        return "WARNING"
    if result.signal in c.INSPECTION_BLOCKED_SIGNALS:
        return "INSPECTION_BLOCKED"
    # No clean page, no UP. This covers a 403 or 503 answer, a certificate problem, a timeout
    # on a site where timeouts never alert, and so on. Whether an email is sent is decided
    # elsewhere and has not changed.
    if result.signal != c.OK or result.status_code is None:
        return "UNKNOWN"
    if site_state["slow_active"]:
        return "SLOW"
    return "UP"


def _handle_down(site, site_state, result, now, settings) -> list:
    site_state["inspection_blocked"] = False
    site_state["down_inconclusive_since"] = None
    site_state["down_signal"] = result.signal
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
        return [_down_alert(site, site_state, result, now, settings, reminder=False)]
    if now - last >= reminder_seconds:
        return [_down_alert(site, site_state, result, now, settings, reminder=True)]
    return []


def _clears_outage(site_state, result) -> bool:
    """Does this answer end an open outage?

    A clean page always does. A challenge or block page proves DNS, TCP, TLS and the
    Cloudflare edge work, so it ends a DNS or connection outage. It says nothing about the
    origin server, so a Cloudflare 52x outage stays open. On a normal (non-strict) site any
    answer from the server counts, as it always has.
    """
    if result.signal == c.OK:
        return True
    if result.signal in c.INSPECTION_BLOCKED_SIGNALS:
        return site_state["down_signal"] in DNS_OR_CONNECTION
    if result.signal == c.HTTP_ERROR:
        return not result.strict
    return False


def _handle_not_down(site, site_state, result, now, settings) -> list:
    alerts = []
    signal = result.signal
    cloudflare_site = site.behind_cloudflare or site_state["cloudflare_seen"]

    if site_state["status"] == "down":
        if not _clears_outage(site_state, result):
            # Inconclusive answer. Keep the outage open, send nothing (not even a reminder).
            if site_state["down_inconclusive_since"] is None:
                site_state["down_inconclusive_since"] = now
            site_state["inspection_blocked"] = signal in c.INSPECTION_BLOCKED_SIGNALS
            return []
        site_state["pending_recovery"] = {
            "down_since": site_state["down_since"],
            "recovered_at": now,
            "last_up_at": site_state["last_up_at"],
        }
        site_state.update(down_since=None, down_notified_at=None, down_signal=None, down_inconclusive_since=None)
    site_state["status"] = "up"

    if site_state["pending_recovery"]:
        alerts.append(_recovered_alert(site, site_state, result, now, settings))

    # Any page that is not a clean normal page cannot be used for content checks.
    site_state["inspection_blocked"] = signal != c.OK
    if signal == c.OK or (signal == c.HTTP_ERROR and not result.strict):
        site_state["last_up_at"] = now

    if signal == c.OK:
        site_state["tls_warn_active"] = False
        alerts.extend(_slow_alerts(site, site_state, result, now, settings))
        alerts.extend(_text_alerts(site, site_state, result, now, settings))
    elif signal == c.TLS_WARN and not cloudflare_site:
        alerts.extend(_tls_warning(site, site_state, result, now, settings))
    elif signal == c.CF_CONFIG_ERROR and result.config_confirmed:
        alerts.extend(_config_warning(site, site_state, result, now, settings))
    elif cloudflare_site:
        site_state["tls_warn_active"] = False   # the certificate we see is Cloudflare's, not the client's
    return alerts


def _slow_alerts(site, site_state, result, now, settings) -> list:
    slow = result.response_time is not None and result.response_time > site.slow_threshold_seconds
    if not slow:
        site_state["slow_active"] = False
        return []
    already_slow = site_state["slow_active"]
    site_state["slow_active"] = True
    if already_slow:
        return []  # one warning per slow period, not one every run
    last = site_state["last_slow_alert"]
    if last is not None and now - last < SLOW_WARNING_COOLDOWN_SECONDS:
        return []
    return [
        Alert(
            kind=WARNING,
            site_name=site.name,
            url=site.url,
            summary=f"Slow response ({result.response_time:.1f}s, limit is {site.slow_threshold_seconds:g}s)",
            details=[("Response time", f"{result.response_time:.2f}s")] + _evidence(result),
            ts=now,
            tag="slow",
            site_id=site.site_id,
        )
    ]


def _episode_warning(site_state, now, active_key, last_key, reminder_seconds, make_alert) -> list:
    """A warning that is sent once, repeats daily while it lasts, and cools down when it flaps."""
    last = site_state[last_key]
    was_active = site_state[active_key]
    site_state[active_key] = True
    if last is not None:
        # Same problem continuing gets a reminder. A new episode right after a recovery
        # waits an hour, so a flapping site cannot flood the inbox.
        wait = reminder_seconds if was_active else SLOW_WARNING_COOLDOWN_SECONDS
        if now - last < wait:
            return []
    return [make_alert()]


def _refused_warning(site, site_state, result, now, settings) -> list:
    """Warning for a site whose refused connections are not treated as an outage."""

    def make():
        return Alert(
            kind=WARNING,
            site_name=site.name,
            url=site.url,
            summary=f"{result.error}. Counted as a warning, not DOWN, because of this site's setting.",
            details=[
                ("Checks", f"All {result.attempts} attempts failed"),
                ("Setting", "connection_refused_is_warning is on for this site"),
            ] + _evidence(result),
            ts=now,
            tag="refused",
            site_id=site.site_id,
        )

    return _episode_warning(site_state, now, "refused_active", "last_refused_alert", REFUSED_REMINDER_SECONDS, make)


def _tls_warning(site, site_state, result, now, settings) -> list:
    def make():
        return Alert(
            kind=WARNING,
            site_name=site.name,
            url=site.url,
            summary="The SSL certificate is expired or invalid. Visitors will see a browser warning.",
            details=_evidence(result),
            ts=now,
            tag="tls",
            site_id=site.site_id,
        )

    return _episode_warning(site_state, now, "tls_warn_active", "last_tls_alert", WARNING_REMINDER_SECONDS, make)


def _config_warning(site, site_state, result, now, settings) -> list:
    """Cloudflare says the SITE is misconfigured (for example 1016). Confirmed on 3 visits."""
    code = result.cf_code
    meaning = c.CF_CONFIG_ERRORS.get(code, "Cloudflare reports a configuration problem with this site.")

    def make():
        return Alert(
            kind=WARNING,
            site_name=site.name,
            url=site.url,
            summary=f"Cloudflare error {code}. {meaning}",
            details=[("Checks", f"Seen on all {result.attempts} visits, at least {settings.retry_gap_seconds:g} seconds apart")]
            + _evidence(result),
            ts=now,
            tag="cfconfig",
            site_id=site.site_id,
        )

    return _episode_warning(site_state, now, "config_error_active", "last_config_alert", WARNING_REMINDER_SECONDS, make)


def _text_alerts(site, site_state, result, now, settings) -> list:
    """expected_text is only judged on a clean normal page, never on a challenge or error page."""
    if not site.expected_text or result.status_code != 200:
        return []
    if not result.text_missing:
        site_state["text_missing_active"] = False
        return []

    def make():
        return Alert(
            kind=WARNING,
            site_name=site.name,
            url=site.url,
            summary="The page loads, but the expected text is missing from it.",
            details=[("Expected text", site.expected_text)] + _evidence(result),
            ts=now,
            tag="text",
            site_id=site.site_id,
        )

    return _episode_warning(site_state, now, "text_missing_active", "last_text_alert", WARNING_REMINDER_SECONDS, make)


def _evidence(result) -> list:
    """The proof that goes into every DOWN, RECOVERED and WARNING email."""
    attempts = result.attempt_log or [result]
    rows = [("Signal", result.signal)]
    rows.append(("HTTP status", ", ".join(str(a.status_code) if a.status_code else "no response" for a in attempts)))
    ray = next((a.cf_ray for a in attempts if a.cf_ray), None)
    mitigated = next((a.cf_mitigated for a in attempts if a.cf_mitigated), None)
    codes = [str(a.cf_code) for a in attempts if a.cf_code]
    if codes:
        rows.append(("Cloudflare error code", ", ".join(codes)))
    if ray:
        rows.append(("Cloudflare cf-ray", ray))
    if mitigated:
        rows.append(("Cloudflare cf-mitigated", mitigated))
    probes = next((a.probes for a in reversed(attempts) if a.probes), None)
    if probes:
        for resolver, answer in probes.dns.items():
            rows.append((f"DNS via {resolver}", answer))
        rows.append((f"TCP port {probes.port}", probes.tcp))
        rows.append(("TLS handshake", probes.tls))
    rows.append(
        ("Response time", ", ".join(f"{a.response_time:.2f}s" if a.response_time is not None else "none" for a in attempts))
    )
    for number, attempt in enumerate(attempts, start=1):
        rows.append((f"Attempt {number}", f"{fmt_utc(attempt.started_at)} / {fmt_time(attempt.started_at)}"))
    return rows


def _down_alert(site, site_state, result, now, settings, reminder: bool) -> Alert:
    details = [
        ("Checks", f"{result.attempts} attempts, at least {settings.retry_gap_seconds:g} seconds apart, all failed"),
        ("Down since", fmt_time(site_state["down_since"])),
    ]
    if reminder:
        details.append(("Down for", _hours_text(now - site_state["down_since"])))
    return Alert(
        kind=DOWN,
        site_name=site.name,
        url=site.url,
        summary=result.error or "Website is not responding",
        details=details + _evidence(result),
        ts=now,
        tag="down",
        site_id=site.site_id,
        headline="STILL DOWN" if reminder else "",
    )


def _hours_text(seconds: float) -> str:
    hours = max(1, math.ceil(seconds / 3600))
    return f"{hours} hour" + ("" if hours == 1 else "s")


def _recovered_alert(site, site_state, result, now, settings) -> Alert:
    pending = site_state["pending_recovery"]
    # Checks run every few hours, so the true downtime is "up to" the gap between the last
    # run that saw the site working and the run that saw it working again.
    since = pending.get("last_up_at") or pending["down_since"]
    details = [
        (
            "Downtime",
            f"up to {_hours_text(pending['recovered_at'] - since)} (checked every {settings.check_every_hours:g} hours)",
        ),
        ("Down since", fmt_time(pending["down_since"])),
    ]
    return Alert(
        kind=RECOVERED,
        site_name=site.name,
        url=site.url,
        summary="Website is back online",
        details=details + _evidence(result),
        ts=now,
        tag="recovered",
        site_id=site.site_id,
    )


def apply_delivery(state: dict, alert: Alert, now: float) -> None:
    """Record that an alert was really delivered. Undelivered alerts are retried next run."""
    site_state = state["sites"].get(alert.site_id)
    if site_state is None:
        return
    if alert.tag == "down":
        site_state["down_notified_at"] = now
    elif alert.tag == "recovered":
        site_state["pending_recovery"] = None
    elif alert.tag == "slow":
        site_state["last_slow_alert"] = now
    elif alert.tag == "refused":
        site_state["last_refused_alert"] = now
    elif alert.tag == "tls":
        site_state["last_tls_alert"] = now
    elif alert.tag == "text":
        site_state["last_text_alert"] = now
    elif alert.tag == "cfconfig":
        site_state["last_config_alert"] = now
