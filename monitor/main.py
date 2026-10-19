"""Command line entry point.

    python -m monitor.main                run all checks and send alerts
    python -m monitor.main --dry-run      run all checks, print results, send nothing
    python -m monitor.main --test-alert   send a test message to every configured channel
    python -m monitor.main --notify-crash used by the workflow when the monitor itself crashes

Only the standard library is imported at the top, so the crash alert still works
even if installing the dependencies is what failed.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time

from . import heartbeat
from . import state as state_store
from .alerts import CRASH, TEST, Alert
from .config import ConfigError, load_dotenv, load_settings, load_sites
from .log import mask_in_actions, register_sensitive, setup_logging
from .logic import apply_delivery, evaluate_uptime, started_alert
from .notifiers import build_notifiers, dispatch
from .timeutil import fmt_time

log = logging.getLogger("monitor")

CRASH_ALERT_COOLDOWN_SECONDS = 6 * 3600


def _parse_args(argv):
    parser = argparse.ArgumentParser(prog="monitor", description="Website uptime and security monitor.")
    parser.add_argument("--dry-run", action="store_true", help="run all checks and print results, send nothing")
    parser.add_argument("--test-alert", action="store_true", help="send a test message to every configured channel")
    parser.add_argument("--notify-crash", action="store_true", help="send a 'monitor is broken' alert")
    return parser.parse_args(argv)


def _protect_secrets(settings) -> None:
    """Hide passwords and email addresses from every log line."""
    register_sensitive(settings.sensitive_values())
    if settings.in_actions:
        mask_in_actions(settings.sensitive_values())


def _protect_sites(settings, sites) -> None:
    """Hide client names, URLs and domains from public logs (not when testing on your PC)."""
    values = []
    for site in sites:
        values.extend([site.name, site.url, site.host, site.expected_domain])
    if not settings.real_names_in_logs:
        register_sensitive(values)
    if settings.in_actions:
        mask_in_actions(values)


def _warn_about_missing_basics(settings) -> None:
    if not settings.state_salt:
        log.warning("STATE_SALT is not set. Set it to any random text so stored IDs cannot be guessed.")
    if not settings.email_enabled:
        log.warning("Email is not configured (SMTP_USER, SMTP_PASSWORD and EMAIL_TO are needed).")


# --------------------------------------------------------------------------------------
# --test-alert
# --------------------------------------------------------------------------------------
def run_test_alert(settings) -> int:
    notifiers = build_notifiers(settings)
    if not notifiers:
        log.error("No notification channel is configured. Nothing to test.")
        return 1
    try:
        site_count = len(load_sites(settings))
    except ConfigError:
        site_count = 0
    alert = Alert(
        kind=TEST,
        site_name="Website Monitor",
        url="",
        summary="This is a test message. If you can read it, this channel works.",
        details=[("Websites configured", str(site_count)), ("Channels", ", ".join(n.name for n in notifiers))],
        ts=time.time(),
    )
    result = dispatch([alert], notifiers)
    for channel, ok in result.channels.items():
        log.info("Test alert via %s: %s", channel, "SENT" if ok else "FAILED")
    return 0 if any(result.channels.values()) else 1


# --------------------------------------------------------------------------------------
# --notify-crash
# --------------------------------------------------------------------------------------
def run_notify_crash(settings) -> int:
    notifiers = build_notifiers(settings)
    if not notifiers:
        log.error("Monitor crashed, but no notification channel is configured.")
        return 1
    state = state_store.load_state(settings.state_path)
    now = time.time()
    last = state["meta"].get("last_crash_alert")
    if last and now - last < CRASH_ALERT_COOLDOWN_SECONDS:
        log.info("A crash alert was already sent in the last 6 hours, not sending another.")
        return 0

    details = [("Next step", "Open the run log in GitHub Actions to see the error")]
    if os.environ.get("GITHUB_RUN_ID") and os.environ.get("GITHUB_REPOSITORY"):
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        details.append(("Run log", f"{server}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"))
    alert = Alert(
        kind=CRASH,
        site_name="Website Monitor",
        url="",
        summary="The monitor script crashed. Your websites are NOT being checked until this is fixed.",
        details=details,
        ts=now,
        tag="crash",
    )
    result = dispatch([alert], notifiers)
    if result.delivered[0]:
        state["meta"]["last_crash_alert"] = now
        state_store.save_state(settings.state_path, state)
    return 0 if result.delivered[0] else 1


# --------------------------------------------------------------------------------------
# normal run and --dry-run
# --------------------------------------------------------------------------------------
def run_checks(settings, sites, dry_run: bool) -> int:
    from .checks.uptime import run_uptime_checks  # imported here so --notify-crash needs no packages

    started = time.time()
    state = state_store.load_state(settings.state_path)
    removed = state_store.prune_removed_sites(state, [s.site_id for s in sites])
    if removed:
        log.info("Forgot the saved state of %d removed website(s).", removed)

    log.info("Checking %d website(s)%s ...", len(sites), " (dry run, nothing will be sent)" if dry_run else "")
    results = run_uptime_checks(sites, settings)

    alerts, internal_errors = [], 0
    for site in sites:
        result = results[site.site_id]
        if result is None:
            internal_errors += 1
            continue
        site_state = state_store.get_site_state(state, site.site_id)
        alerts.extend(evaluate_uptime(site, site_state, result, started, settings))
        _log_site_result(settings, site, result, site_state)

    if sites and not state["meta"].get("started_notified"):
        alerts.append(started_alert(len(sites), started))

    if dry_run:
        _print_dry_run_summary(settings, alerts)
        return 1 if internal_errors else 0

    if alerts:
        notifiers = build_notifiers(settings)
        if not notifiers:
            log.warning("%d alert(s) could not be sent because no channel is configured.", len(alerts))
        else:
            outcome = dispatch(alerts, notifiers)
            now = time.time()
            for alert, delivered in zip(alerts, outcome.delivered):
                if delivered:
                    apply_delivery(state, alert, now)
                else:
                    log.warning("An alert was not delivered and will be retried on the next run.")

    state["meta"]["last_run"] = started
    state_store.save_state(settings.state_path, state)
    log.info("Done in %.1fs.", time.time() - started)

    if internal_errors:
        log.error("%d website(s) could not be checked because of an internal error.", internal_errors)
        return 1
    heartbeat.ping(settings.healthcheck_url)
    return 0


def _log_site_result(settings, site, result, site_state) -> None:
    name = settings.log_name(site)
    if result.ok:
        log.info("%-9s UP    HTTP %s  %.2fs", name, result.status_code, result.response_time or 0)
    else:
        since = fmt_time(site_state["down_since"]) if site_state.get("down_since") else "now"
        log.warning("%-9s DOWN  %s (down since %s)", name, result.error, since)


def _print_dry_run_summary(settings, alerts) -> None:
    print()
    if not alerts:
        print("No alerts would be sent.")
        return
    print(f"{len(alerts)} alert(s) would be sent:")
    for alert in alerts:
        if settings.real_names_in_logs:
            print(f"  {alert.emoji} {alert.label}: {alert.site_name} - {alert.summary}")
        else:
            print(f"  {alert.emoji} {alert.label} (details hidden in public logs)")


def main(argv=None) -> int:
    args = _parse_args(argv)
    load_dotenv()
    setup_logging()
    try:
        settings = load_settings()
        _protect_secrets(settings)
        if args.test_alert:
            return run_test_alert(settings)
        if args.notify_crash:
            return run_notify_crash(settings)
        sites = load_sites(settings)
        _protect_sites(settings, sites)
        _warn_about_missing_basics(settings)
        return run_checks(settings, sites, dry_run=args.dry_run)
    except ConfigError as exc:
        log.error("Settings problem. %s", exc)
        return 2
    except Exception:
        log.exception("The monitor crashed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
