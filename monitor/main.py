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
from collections import Counter

from . import heartbeat
from . import state as state_store
from .alerts import CRASH, TEST, WARNING, Alert
from .checks import classify
from .checks.network import dns_words
from .config import (
    ConfigError,
    load_dotenv,
    load_settings,
    load_sites,
    load_sites_report,
    warn_about_removed_settings,
)
from .log import mask_in_actions, register_sensitive, setup_logging
from .logic import apply_delivery, evaluate_uptime
from .notifiers import build_notifiers, dispatch

log = logging.getLogger("monitor")

CRASH_ALERT_COOLDOWN_SECONDS = 6 * 3600
DNS_DEGRADED_THRESHOLD = 2   # more than this many sites with failed DNS lookups = "degraded"


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
        values.extend([site.name, site.url, site.host, site.expected_domain, site.expected_text])
    if not settings.real_names_in_logs:
        register_sensitive(values)
    if settings.in_actions:
        mask_in_actions(values)


def _warn_about_missing_basics(settings) -> None:
    warn_about_removed_settings()
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
def run_checks(settings, sites, dry_run: bool, skipped: int = 0, keep_ids=()) -> int:
    from .checks.uptime import run_uptime_checks  # imported here so --notify-crash needs no packages

    started = time.time()
    state = state_store.load_state(settings.state_path)
    # Sites skipped for a config typo keep their saved state, so a typo cannot wipe a baseline.
    removed = state_store.prune_removed_sites(state, [s.site_id for s in sites] + list(keep_ids))
    if removed:
        log.info("Forgot the saved state of %d removed website(s).", removed)
    if state.get("_fresh"):
        log.info("Saved state was missing, so everything is learned from scratch (no change alerts this run).")
    cloudflare_seen = {
        site.site_id for site in sites if state_store.get_site_state(state, site.site_id)["cloudflare_seen"]
    }

    log.info("Checking %d website(s)%s ...", len(sites), " (dry run, nothing will be sent)" if dry_run else "")
    results = run_uptime_checks(sites, settings, cloudflare_seen)

    alerts, rows, advice, internal_errors = [], [], [], 0
    counts = Counter()
    paused, resumed, auto_detected = [], [], []
    dns_lookup_failures = 0
    unrecognised_codes = Counter()   # Cloudflare 1xxx codes we have no rule for, by number of sites
    for site in sites:
        result = results[site.site_id]
        if result is None:
            internal_errors += 1
            continue
        site_state = state_store.get_site_state(state, site.site_id)
        was_blocked = site_state["inspection_blocked"]
        alerts.extend(evaluate_uptime(site, site_state, result, started, settings))

        counts[site_state["last_state"]] += 1
        if result.verdict == classify.VERDICT_MIXED:
            counts["mixed"] += 1
        if result.signal in classify.INSPECTION_BLOCKED_SIGNALS:
            if not was_blocked:
                paused.append(site.name)   # emails are private, so real names are fine here
        elif result.signal == classify.OK and was_blocked:
            resumed.append(site.name)
        if result.cloudflare and not site.behind_cloudflare:
            auto_detected.append(settings.log_name(site))
        if _dns_lookup_failed(result):
            dns_lookup_failures += 1
        if result.signal == classify.CF_VISITOR_BLOCK and result.cf_code and not classify.is_recognised_cf_code(result.cf_code):
            unrecognised_codes[str(result.cf_code)] += 1
        rows.append(_table_row(settings, site, result, site_state))
        advice.append(_advice_row(settings, site, result))
        if settings.real_names_in_logs:   # per-site lines only on your own PC, never in public logs
            log.info("%-24s %-18s %s", settings.log_name(site), site_state["last_state"], _short_result(result))

    if settings.notify_on_blocked_change and not state.get("_fresh") and (paused or resumed):
        alerts.append(_scan_change_alert(paused, resumed, started))

    stats = {
        "sites": len(sites),
        "UP": counts["UP"],
        "SLOW": counts["SLOW"],
        "DOWN": counts["DOWN"],
        "WARNING": counts["WARNING"],
        "UNKNOWN": counts["UNKNOWN"],
        "INSPECTION_BLOCKED": counts["INSPECTION_BLOCKED"],
        "mixed": counts["mixed"],
        "skipped_config": skipped,
        # Read by the daily summary. A failed DNS lookup is never a DNS_FAIL, so if the lookups
        # themselves stop working the DNS_FAIL signal goes quietly dead. This makes that visible.
        "dns_lookup_failures": dns_lookup_failures,
        "dns_degraded": dns_lookup_failures > DNS_DEGRADED_THRESHOLD,
        "unrecognised_cf_codes": dict(unrecognised_codes),
    }
    _log_aggregate(stats)

    if dry_run:
        _print_dry_run(settings, rows, advice, alerts, auto_detected, stats)
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
    state["meta"]["last_run_stats"] = stats      # read by the daily summary
    state_store.save_state(settings.state_path, state)
    log.info("Done in %.1fs.", time.time() - started)

    if internal_errors:
        log.error("%d website(s) could not be checked because of an internal error.", internal_errors)
        return 1
    heartbeat.ping(settings.healthcheck_url)
    return 0


def _scan_change_alert(paused, resumed, now) -> Alert:
    parts = []
    details = []
    if paused:
        parts.append(f"Content scanning paused for {len(paused)} site{'s' if len(paused) != 1 else ''}")
        details.append(("Paused", ", ".join(paused)))
    if resumed:
        parts.append(f"content scanning resumed for {len(resumed)} site{'s' if len(resumed) != 1 else ''}")
        details.append(("Resumed", ", ".join(resumed)))
    summary = " and ".join(parts)
    return Alert(kind=WARNING, site_name="Website Monitor", url="", summary=summary[0].upper() + summary[1:] + ".",
                 details=details, ts=now)


def _log_aggregate(stats) -> None:
    """The only per-run summary that goes into public logs: counts, never names."""
    log.info(
        "%d site(s) checked: %d UP, %d SLOW, %d DOWN, %d WARNING, %d UNKNOWN (no clean page)",
        stats["sites"], stats["UP"], stats["SLOW"], stats["DOWN"], stats["WARNING"], stats["UNKNOWN"],
    )
    if stats["INSPECTION_BLOCKED"]:
        log.info("%d sites inspection-blocked", stats["INSPECTION_BLOCKED"])
    if stats["mixed"]:
        log.info("%d site(s) showed mixed failure signals: no alert, will look again next run", stats["mixed"])
    if stats["skipped_config"]:
        log.warning("%d site entr%s skipped because of config problems", stats["skipped_config"],
                    "y" if stats["skipped_config"] == 1 else "ies")
    if stats["dns_degraded"]:
        log.warning(
            "DNS checking is degraded this run: the lookups to 1.1.1.1 and dns.google failed for %d sites, "
            "so DNS_FAIL cannot fire until they work again",
            stats["dns_lookup_failures"],
        )
    for code, count in sorted(stats["unrecognised_cf_codes"].items()):
        log.info("unrecognised Cloudflare code %s seen on %d site%s", code, count, "" if count == 1 else "s")


def _short_result(result) -> str:
    code = result.status_code if result.status_code else "-"
    ms = f"{result.response_time * 1000:.0f}ms" if result.response_time is not None else "-"
    return f"{result.signal} HTTP {code} {ms}" + (" (mixed signals)" if result.verdict == classify.VERDICT_MIXED else "")


TABLE_HEADERS = ["SITE", "STATE", "HTTP", "SIGNAL", "DNS(1.1.1.1 / 8.8.8.8)", "TCP443", "TLS", "MS", "ATTEMPT TIMES (UTC)", "NOTE"]


def _table_row(settings, site, result, site_state) -> list:
    attempts = result.attempt_log or [result]
    probes = next((a.probes for a in reversed(attempts) if a.probes), None)
    notes = []
    if result.verdict == classify.VERDICT_MIXED:
        notes.append("mixed failure signals, no alert, re-check next run")
    if result.cloudflare and not site.behind_cloudflare:
        notes.append("Cloudflare detected, set behind_cloudflare=true")
    if result.marker:
        notes.append(f"matched {result.marker}")
    if result.note:
        notes.append(result.note)
    if result.text_missing:
        notes.append("expected_text missing (confirmed)")
    if site_state["refused_active"]:
        notes.append("refused connection counted as a warning")
    if result.signal == classify.CF_VISITOR_BLOCK and result.cf_code and not classify.is_recognised_cf_code(result.cf_code):
        notes.append(f"unrecognised Cloudflare code {result.cf_code} (silent, listed in the daily summary)")
    if site.uptime_source == "external":
        notes.append("uptime owned by external monitor")
    return [
        settings.log_name(site),
        site_state["last_state"],
        "/".join(str(a.status_code) if a.status_code else "-" for a in attempts),
        "MIXED" if result.verdict == classify.VERDICT_MIXED else result.signal,
        " / ".join(dns_words(probes.dns.get(name, "-"), short=True) for name in ("1.1.1.1", "8.8.8.8")) if probes else "-",
        probes.tcp if probes else "-",
        probes.tls if probes else "-",
        "/".join(f"{a.response_time * 1000:.0f}" if a.response_time is not None else "-" for a in attempts),
        "/".join(time.strftime("%H:%M:%S", time.gmtime(a.started_at)) for a in attempts),
        "; ".join(notes) or "-",
    ]


def _dns_lookup_failed(result) -> bool:
    """True if our own DNS lookups (not the site's DNS) failed during any visit."""
    return any(
        a.probes is not None and any(answer == "ERROR" for answer in a.probes.dns.values())
        for a in (result.attempt_log or [result])
    )


ADVICE_HEADERS = ["SITE", "CLOUDFLARE DETECTED", "HTTP SEEN", "WHAT TO SET IN SITES_JSON"]


def _advice_row(settings, site, result) -> list:
    """One line per site telling you which new settings it probably needs. Never edits anything."""
    attempts = result.attempt_log or [result]
    got_response = any(a.status_code is not None for a in attempts)
    detected = "yes" if result.cloudflare else ("no" if got_response else "unknown (no response)")
    todo = []
    if result.verdict == classify.VERDICT_DOWN:
        todo.append(f"failing now ({result.signal}), check this site first")
    if result.cloudflare and not site.behind_cloudflare:
        todo.append('"behind_cloudflare": true')
    if site.behind_cloudflare and got_response and not result.cloudflare:
        todo.append("behind_cloudflare is set but no Cloudflare headers were seen")
    cannot_judge = result.signal in classify.INSPECTION_BLOCKED_SIGNALS or (
        result.signal == classify.HTTP_ERROR and result.verdict != classify.VERDICT_DOWN
    )
    if cannot_judge and site.uptime_source != "external":
        todo.append('"uptime_source": "external" if an external monitor covers it (GitHub cannot judge this site)')
    if result.signal == classify.TLS_WARN and not (site.behind_cloudflare or result.cloudflare):
        todo.append("certificate problem: fix the certificate, or set behind_cloudflare if Cloudflare issues it")
    if not todo:
        todo.append("nothing to change")
    return [
        settings.log_name(site),
        detected,
        "/".join(str(a.status_code) if a.status_code else "-" for a in attempts),
        "; ".join(todo),
    ]


def _print_table(headers, rows) -> None:
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i]) for i in range(len(headers))]
    line = lambda cells: " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()
    print(line(headers))
    print("-+-".join("-" * w for w in widths))
    for row in rows:
        print(line(row))


def _print_dry_run(settings, rows, advice, alerts, auto_detected, stats) -> None:
    print()
    _print_table(TABLE_HEADERS, rows)
    print()
    print("SETTINGS HELP (suggestions only, nothing is changed for you)")
    _print_table(ADVICE_HEADERS, advice)
    print()
    if stats["dns_degraded"]:
        print(f"DNS checking is degraded: lookups failed for {stats['dns_lookup_failures']} site(s), "
              "so DNS_FAIL cannot fire in this run.")
    if auto_detected:
        print(f"Cloudflare was detected on {len(auto_detected)} site(s) that do not have "
              f'"behind_cloudflare": true yet. Add it in SITES_JSON for  ' + ", ".join(auto_detected))
    if stats["skipped_config"]:
        print(f"{stats['skipped_config']} entr{'y' if stats['skipped_config'] == 1 else 'ies'} in SITES_JSON "
              "skipped because of config problems (see the warnings above).")
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
        load = load_sites_report(settings)
        _protect_sites(settings, load.sites)
        _warn_about_missing_basics(settings)
        return run_checks(
            settings,
            load.sites,
            dry_run=args.dry_run or settings.dry_run,
            skipped=load.skipped,
            keep_ids=load.skipped_ids,
        )
    except ConfigError as exc:
        log.error("Settings problem. %s", exc)
        return 2
    except Exception:
        log.exception("The monitor crashed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
