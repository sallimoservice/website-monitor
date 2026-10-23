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

- Trouble behind Cloudflare (a mix of 5xx answers passed through from the server, Cloudflare 52x
  errors and timeouts) is never DOWN unless all 3 visits are the same Cloudflare 52x error, but 3
  visits in a row give a WARNING. It repeats every 8 hours while it lasts. Sites that hand their
  uptime to an external monitor get it too: the external monitor owns DOWN, not visibility.

Labels are separate from alerts. A site only gets the label UP when the monitor received a clean
normal page. A 403 or 503 answer, a missing response or a challenge page never earns UP, even
when (as always) no alert is sent for it.
- If an alert could not be delivered by any channel, it is tried again on the next run.

Independent confirmation (checks/confirm.py, on unless CONFIRM_ENABLED=false). The runner is one viewpoint, so
a failure seen only from there is never a DOWN. A site becomes DOWN only when the outside check agrees in two
rounds. Anything else is a WARNING or nothing at all:
  runner fails, outside locations load the site   WARNING "the monitor may be blocked", once a day
  the outside check gave no clear answer          WARNING "could not confirm", once a day
  the failure cleared on the second look          nothing
  many sites failed at the same moment            one summary WARNING (sent by main.py), no DOWN
"Back online" is only sent for an outage that was confirmed AND announced, so none of the warnings above
can ever lead to one. DNS failures need no outside check (two public resolvers already agree).
"""

from __future__ import annotations

import math

from .alerts import DOWN, RECOVERED, WARNING, Alert
from .checks import classify as c
from .checks import confirm
from .checks.network import dns_words
from .state import record_history
from .timeutil import fmt_time, fmt_utc

SLOW_WARNING_COOLDOWN_SECONDS = 3600
REFUSED_REMINDER_SECONDS = 24 * 3600
WARNING_REMINDER_SECONDS = 24 * 3600
DNS_OR_CONNECTION = (c.DNS_FAIL, c.CONN_FAIL)


def evaluate_uptime(site, site_state: dict, result, now: float, settings, confirmation=None) -> list:
    """Update one site's state from a check result and return the alerts to send.

    `confirmation` is what the outside check decided for this site (checks/confirm.py ConfirmOutcome), or None.
    """
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
    if not result.origin_trouble_confirmed:
        site_state["origin_trouble_active"] = False

    is_down = result.verdict == c.VERDICT_DOWN
    outcome = _outside_outcome(site, site_state, result, settings, confirmation) if is_down else None
    unconfirmed = is_down and outcome is not None and outcome.outcome != confirm.OUTCOME_CONFIRMED_DOWN
    if not unconfirmed:
        site_state["blocked_active"] = False
        site_state["unconfirmed_active"] = False
    # A site that is already DOWN stays in the normal DOWN flow. Timeouts, DNS errors,
    # SSL errors and HTTP errors are never downgraded, only refused connections.
    refused_as_warning = (
        is_down
        and result.signal == c.CONN_FAIL
        and site.connection_refused_is_warning
        and site_state["status"] != "down"
    )
    # History: 1 = clean page, 0 = confirmed down, None = unknown (no usable page either way).
    if is_down and not refused_as_warning and not unconfirmed:
        history_flag = False
    elif result.signal == c.OK:
        history_flag = True
    else:
        history_flag = None
    record_history(site_state, now, history_flag, response_ms)

    if refused_as_warning:
        site_state["inspection_blocked"] = False
        alerts = _refused_warning(site, site_state, result, now, settings)
    elif unconfirmed:
        site_state["refused_active"] = False
        alerts = _handle_unconfirmed(site, site_state, result, now, settings, outcome)
    else:
        site_state["refused_active"] = False
        if is_down:
            alerts = _handle_down(site, site_state, result, now, settings, outcome)
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
        or site_state["origin_trouble_active"]
        or site_state["blocked_active"]
        or site_state["unconfirmed_active"]
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


def _outside_outcome(site, site_state, result, settings, confirmation):
    """What the outside check decided for a would-be DOWN, or None when no outside check applies.

    With confirmation on, a would-be DOWN that needs an outside opinion and has none (the step crashed or
    never ran) counts as "could not confirm". A missing answer is never a DOWN.
    """
    if not settings.confirm_enabled:
        return None
    if confirmation is not None:
        return confirmation
    if confirm.is_candidate(site, result, site_state["status"] == "down"):
        return confirm.ConfirmOutcome(confirm.OUTCOME_UNCONFIRMED, "the outside check did not run")
    return None


def _handle_unconfirmed(site, site_state, result, now, settings, outcome) -> list:
    """The runner could not load the site, and the outside check did not confirm an outage."""
    kind = outcome.outcome
    if kind == confirm.OUTCOME_RUNNER_BLOCKED and site_state["status"] == "down":
        # An outage that was confirmed earlier, and now other locations load the site: it is back.
        alerts = _handle_not_down(site, site_state, result, now, settings, outcome)
        alerts.extend(_blocked_warning(site, site_state, result, now, settings, outcome))
        return alerts
    # Only the warning that applies now stays active, so a daily reminder keeps counting from the same episode.
    site_state["blocked_active"] = site_state["blocked_active"] and kind == confirm.OUTCOME_RUNNER_BLOCKED
    site_state["unconfirmed_active"] = site_state["unconfirmed_active"] and kind == confirm.OUTCOME_UNCONFIRMED
    if kind == confirm.OUTCOME_RUNNER_BLOCKED:
        return _blocked_warning(site, site_state, result, now, settings, outcome)
    if kind == confirm.OUTCOME_UNCONFIRMED:
        return _unconfirmed_warning(site, site_state, result, now, settings, outcome)
    return []   # a blip, or one of many sites failing together (main.py sends one summary for those)


def _blocked_warning(site, site_state, result, now, settings, outcome) -> list:
    """Other locations load the site and the monitor cannot. Visitors are probably fine."""

    def make():
        return Alert(
            kind=WARNING,
            site_name=site.name,
            url=site.url,
            summary=(
                "The monitor cannot load this site, but other locations around the world can. The monitor itself "
                "may be blocked by the site's host. This is NOT reported as down."
            ),
            details=[
                ("What to do", "Open the site in a browser. If it loads, the host is probably blocking GitHub's servers. "
                               "Ask the host to allow the IP address below, or hand this site to an external monitor."),
                ("Why not DOWN", outcome.reason),
            ] + confirm.evidence_rows(outcome) + _evidence(result),
            ts=outcome.decided_at or now,
            tag="blocked",
            site_id=site.site_id,
        )

    return _episode_warning(site_state, now, "blocked_active", "last_blocked_alert", WARNING_REMINDER_SECONDS, make)


def _unconfirmed_warning(site, site_state, result, now, settings, outcome) -> list:
    """The monitor cannot load the site and the outside check could not say why. Never a DOWN."""

    def make():
        return Alert(
            kind=WARNING,
            site_name=site.name,
            url=site.url,
            summary=(
                "The monitor cannot load this site and could not confirm from other locations whether it is really "
                "down. It is NOT reported as down. It is checked again on the next run."
            ),
            details=[("Why it is not confirmed", outcome.reason)] + confirm.evidence_rows(outcome) + _evidence(result),
            ts=outcome.decided_at or now,
            tag="unconfirmed",
            site_id=site.site_id,
        )

    return _episode_warning(site_state, now, "unconfirmed_active", "last_unconfirmed_alert", WARNING_REMINDER_SECONDS, make)


def _handle_down(site, site_state, result, now, settings, outcome=None) -> list:
    site_state["inspection_blocked"] = False
    site_state["down_inconclusive_since"] = None
    if result.verdict == c.VERDICT_DOWN:
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
        return [_down_alert(site, site_state, result, now, settings, reminder=False, outcome=outcome)]
    if now - last >= reminder_seconds:
        return [_down_alert(site, site_state, result, now, settings, reminder=True, outcome=outcome)]
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


def _handle_not_down(site, site_state, result, now, settings, outside=None) -> list:
    """`outside` is set only when other locations load a site the monitor cannot: that ends an open outage."""
    alerts = []
    signal = result.signal
    cloudflare_site = site.behind_cloudflare or site_state["cloudflare_seen"]

    if site_state["status"] == "down":
        if outside is None and result.origin_trouble_confirmed and site_state["down_signal"] == c.CF_ORIGIN_ERROR:
            # The origin is still in trouble, only the kind of error changed (522, then 504 ...).
            # That is the same outage, so the 8 hour reminders carry on.
            return _handle_down(site, site_state, result, now, settings)
        if outside is None and not _clears_outage(site_state, result):
            # Inconclusive answer. Keep the outage open, send nothing (not even a reminder).
            if site_state["down_inconclusive_since"] is None:
                site_state["down_inconclusive_since"] = now
            site_state["inspection_blocked"] = signal in c.INSPECTION_BLOCKED_SIGNALS
            return []
        if site_state["down_notified_at"] is not None:
            # Only an outage the owner was actually told about gets a "back online" email. If the DOWN
            # email never got through, saying "back online" would be about something they never saw.
            site_state["pending_recovery"] = {
                "down_since": site_state["down_since"],
                "recovered_at": now,
                "last_up_at": site_state["last_up_at"],
            }
        site_state.update(down_since=None, down_notified_at=None, down_signal=None, down_inconclusive_since=None)
    site_state["status"] = "up"

    if site_state["pending_recovery"]:
        alerts.append(_recovered_alert(site, site_state, result, now, settings, outside))

    # Any page that is not a clean normal page cannot be used for content checks.
    site_state["inspection_blocked"] = signal != c.OK
    if signal == c.OK or (signal == c.HTTP_ERROR and not result.strict) or outside is not None:
        site_state["last_up_at"] = now

    if signal == c.OK:
        site_state["tls_warn_active"] = False
        alerts.extend(_slow_alerts(site, site_state, result, now, settings))
        alerts.extend(_text_alerts(site, site_state, result, now, settings))
    elif signal == c.TLS_WARN and not cloudflare_site:
        alerts.extend(_tls_warning(site, site_state, result, now, settings))
    elif signal == c.CF_CONFIG_ERROR and result.config_confirmed:
        alerts.extend(_config_warning(site, site_state, result, now, settings))
    elif result.origin_trouble_confirmed:
        alerts.extend(_origin_warning(site, site_state, result, now, settings))
    elif cloudflare_site:
        site_state["tls_warn_active"] = False   # the certificate we see is Cloudflare's, not the client's
    return alerts


def _slow_alerts(site, site_state, result, now, settings) -> list:
    slow = result.response_time is not None and result.response_time > site.slow_threshold_seconds
    if not slow:
        site_state["slow_active"] = False
        site_state["slow_alert_pending"] = False
        return []
    already_slow = site_state["slow_active"]
    site_state["slow_active"] = True
    if already_slow and not site_state["slow_alert_pending"]:
        return []  # one warning per slow period, not one every run
    last = site_state["last_slow_alert"]
    if last is not None and now - last < SLOW_WARNING_COOLDOWN_SECONDS:
        return []
    site_state["slow_alert_pending"] = True   # cleared only when the email is really delivered
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


def _origin_warning(site, site_state, result, now, settings) -> list:
    """The server behind Cloudflare is overloaded or broken. A warning to judge, never a DOWN."""
    attempts = result.attempt_log or [result]
    seen = ", ".join(f"HTTP {a.status_code}" if a.status_code else "no answer (timeout)" for a in attempts)

    extra = []
    if any(a.status_code == 520 for a in attempts):
        extra = [("About HTTP 520", "Cloudflare got an empty or unexpected answer from the server. The server may be failing, "
                  "or its firewall may be rejecting this monitor while real visitors are fine. Open the site in a browser to tell which.")]

    def make():
        return Alert(
            kind=WARNING,
            site_name=site.name,
            url=site.url,
            summary=(
                f"The server behind Cloudflare looks overloaded or broken. On {len(attempts)} visits in a row "
                f"the result was {seen}."
            ),
            details=[("Checks", f"{len(attempts)} visits, at least {settings.retry_gap_seconds:g} seconds apart, all in trouble")]
            + extra
            + _evidence(result),
            ts=now,
            tag="origin",
            site_id=site.site_id,
        )

    return _episode_warning(
        site_state, now, "origin_trouble_active", "last_origin_alert", settings.down_reminder_hours * 3600, make
    )


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
            rows.append((f"DNS via {resolver}", dns_words(answer)))
        rows.append((f"TCP port {probes.port}", probes.tcp))
        rows.append(("TLS handshake", probes.tls))
    rows.append(
        ("Response time", ", ".join(f"{a.response_time:.2f}s" if a.response_time is not None else "none" for a in attempts))
    )
    for number, attempt in enumerate(attempts, start=1):
        rows.append((f"Attempt {number}", f"{fmt_utc(attempt.started_at)} / {fmt_time(attempt.started_at)}"))
    return rows


def _down_alert(site, site_state, result, now, settings, reminder: bool, outcome=None) -> Alert:
    details = [
        ("Checks", f"{result.attempts} attempts, at least {settings.retry_gap_seconds:g} seconds apart, all failed"),
        ("Down since", fmt_time(site_state["down_since"])),
    ]
    if reminder:
        details.append(("Down for", _hours_text(now - site_state["down_since"])))
    summary = result.error or "Website is not responding"
    outside = []
    if outcome is not None:
        summary += ". Other locations around the world could not load it either."
        details.append(("Confirmed", outcome.reason))
        outside = confirm.evidence_rows(outcome)
    return Alert(
        kind=DOWN,
        site_name=site.name,
        url=site.url,
        summary=summary,
        details=details + outside + _evidence(result),
        ts=now,
        tag="down",
        site_id=site.site_id,
        headline="STILL DOWN" if reminder else "",
    )


def _hours_text(seconds: float) -> str:
    hours = max(1, math.ceil(seconds / 3600))
    return f"{hours} hour" + ("" if hours == 1 else "s")


def _recovered_alert(site, site_state, result, now, settings, outside=None) -> Alert:
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
    if outside is not None:
        details.append(("How it was seen", "Other locations around the world can load it again. The monitor itself still "
                                           "cannot, so the monitor may be blocked."))
        details.extend(confirm.evidence_rows(outside))
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
        site_state["slow_alert_pending"] = False
    elif alert.tag == "refused":
        site_state["last_refused_alert"] = now
    elif alert.tag == "tls":
        site_state["last_tls_alert"] = now
    elif alert.tag == "text":
        site_state["last_text_alert"] = now
    elif alert.tag == "cfconfig":
        site_state["last_config_alert"] = now
    elif alert.tag == "origin":
        site_state["last_origin_alert"] = now
    elif alert.tag == "blocked":
        site_state["last_blocked_alert"] = now
    elif alert.tag == "unconfirmed":
        site_state["last_unconfirmed_alert"] = now
