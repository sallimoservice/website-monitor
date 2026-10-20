"""Uptime check. Visits each website, labels what happened, and decides if it is DOWN.

How a run works
  Round 1  every website is visited once, all at the same time.
  Round 2  only websites whose visit looked like a real outage are visited again,
           at least 60 seconds after the START of their previous visit.
  Round 3  the same again for websites that are still failing.
A website is only DOWN when all three visits agree (see classify.compute_verdict).
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import Optional

import requests

from . import classify
from .network import Probes, run_probes

log = logging.getLogger("monitor.uptime")

# Headers of a normal desktop Chrome browser. The User-Agent comes from the settings.
BASE_HEADERS = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
}
MAX_BODY_BYTES = 2_000_000


@dataclass
class UptimeResult:
    """One visit (attempt). The final result of a site also carries all its attempts."""

    signal: str = classify.OTHER_FAIL
    status_code: Optional[int] = None
    response_time: Optional[float] = None   # seconds
    error: Optional[str] = None             # plain-English reason when something failed
    started_at: float = 0.0                 # Unix time this visit began
    final_url: Optional[str] = None         # where we ended up after redirects
    # Page HTML for the content checks. ONLY kept for a clean normal page. A challenge,
    # block or error page is dropped inside check_once and never stored anywhere.
    body: Optional[str] = None
    note: Optional[str] = None              # extra remark for the log (never changes up/down)
    cf_ray: Optional[str] = None
    cf_mitigated: Optional[str] = None
    marker: Optional[str] = None            # name of the challenge marker that matched
    cf_code: Optional[int] = None           # Cloudflare 1xxx code, when the page showed one
    cloudflare: bool = False                # the answer came through Cloudflare
    probes: Optional[Probes] = None
    # Filled in on the final result of a site:
    attempts: int = 1
    attempt_log: list = field(default_factory=list, repr=False)
    verdict: str = classify.VERDICT_NOT_DOWN
    strict: bool = False
    text_missing: bool = False              # expected_text confirmed missing on a normal page
    config_confirmed: bool = False          # a site-side Cloudflare error seen on every visit

    @property
    def ok(self) -> bool:
        return self.signal == classify.OK


def _decode(raw: bytes, encoding: Optional[str]) -> str:
    try:
        return raw.decode(encoding or "utf-8", errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def check_once(site, settings) -> UptimeResult:
    """One single visit to the site. Never raises; failures come back as a result."""
    started_at = time.time()
    timer = time.perf_counter()
    headers = {**BASE_HEADERS, "User-Agent": settings.user_agent}
    failure_kind = None
    response = None
    try:
        with requests.get(
            site.url,
            headers=headers,
            timeout=(settings.connect_timeout, settings.read_timeout),
            allow_redirects=True,
            stream=True,
        ) as reply:
            body = bytearray()
            for chunk in reply.iter_content(65536):
                body.extend(chunk)
                if len(body) >= MAX_BODY_BYTES:
                    break
                # Total time limit, so a server that sends one byte at a time cannot stall us.
                if time.perf_counter() - timer > settings.read_timeout * 2:
                    raise requests.exceptions.ReadTimeout()
            response = (
                reply.status_code,
                reply.reason or "",
                {name.lower(): value for name, value in reply.headers.items()},
                _decode(bytes(body), reply.encoding),
                reply.url,
            )
    except requests.exceptions.SSLError as exc:
        # The certificate itself was rejected (expired, wrong name, untrusted) versus a
        # handshake that broke for another reason. Only the first is a certificate warning.
        text = str(exc).lower()
        failure_kind = "ssl_cert" if ("certificate verify failed" in text or "certificate_verify_failed" in text) else "ssl"
    except requests.exceptions.Timeout:
        failure_kind = "timeout"
    except requests.exceptions.TooManyRedirects:
        failure_kind = "redirects"
    except requests.exceptions.ConnectionError:
        failure_kind = "connection"
    except requests.exceptions.RequestException:
        failure_kind = "other"
    elapsed = time.perf_counter() - timer

    # Evidence is collected on every visit, so every alert can show DNS, TCP and TLS results.
    probes = run_probes(site.url, settings.connect_timeout)
    result = UptimeResult(started_at=started_at, probes=probes)

    if response is None:
        result.signal = classify.classify_failure(failure_kind, probes)
        result.error = _failure_text(result.signal, failure_kind, settings)
        return result

    status, reason, reply_headers, text, final_url = response
    verdict = classify.classify_response(status, reply_headers, text)
    result.signal = verdict.signal
    result.marker = verdict.marker
    result.cf_code = verdict.cf_code
    result.status_code = status
    result.response_time = elapsed
    result.final_url = final_url
    result.cf_ray = reply_headers.get("cf-ray")
    result.cf_mitigated = reply_headers.get("cf-mitigated")
    result.cloudflare = classify.is_cloudflare(reply_headers)
    if result.signal == classify.OK:
        result.body = text   # a clean page only; `text` is dropped for every other signal
    elif result.signal == classify.CF_ORIGIN_ERROR:
        result.error = f"Cloudflare error {status} (Cloudflare cannot get a good answer from the server)"
    elif result.signal == classify.HTTP_ERROR:
        result.error = f"Website returned HTTP {status} {reason}".strip()
    return result


def _failure_text(signal: str, kind: Optional[str], settings) -> str:
    if signal == classify.DNS_FAIL:
        return "DNS lookup failed (domain not found)"
    if signal == classify.CONN_FAIL:
        return "Connection failed (server refused or unreachable)"
    if signal == classify.TLS_WARN:
        return "SSL error (certificate problem)"
    if signal == classify.TIMEOUT:
        return f"Timeout (no answer within {settings.read_timeout:g} seconds)"
    if kind == "redirects":
        return "Too many redirects (redirect loop)"
    return "Request failed (connection problem)"


def _attempt(site, settings, previous_start: Optional[float], sleep, clock):
    """One attempt, waiting first if needed. Returns None if our own code failed."""
    try:
        if previous_start is not None:
            wait = previous_start + settings.retry_gap_seconds - clock()
            if wait > 0:
                sleep(wait)
        return check_once(site, settings)
    except Exception:
        log.exception("%s internal check error", settings.log_name(site))
        return None


def _run_round(sites, attempts, settings, sleep, clock) -> dict:
    """Run one attempt for each of `sites` at the same time."""
    workers = max(1, min(len(sites), settings.max_workers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            site.site_id: pool.submit(
                _attempt,
                site,
                settings,
                attempts[site.site_id][-1].started_at if attempts[site.site_id] else None,
                sleep,
                clock,
            )
            for site in sites
        }
        return {site_id: future.result() for site_id, future in futures.items()}


def _text_missing(site, result) -> bool:
    return (
        bool(site.expected_text)
        and classify.page_is_scannable(result.signal, result.status_code)
        and site.expected_text.lower() not in (result.body or "").lower()
    )


def run_uptime_checks(sites, settings, cloudflare_seen_ids=(), sleep=time.sleep, clock=time.time) -> dict:
    """Check every site. Returns {site_id: final UptimeResult, or None if our code failed}.

    None means our own code failed for that site. We never turn that into a DOWN
    alert, because the website itself may be perfectly fine.
    """
    seen = set(cloudflare_seen_ids)
    attempts = {site.site_id: [] for site in sites}
    broken = set()

    pending = list(sites)
    for _round in range(settings.retry_attempts):
        if not pending:
            break
        outcome = _run_round(pending, attempts, settings, sleep, clock)
        retry = []
        for site in pending:
            result = outcome[site.site_id]
            if result is None:
                broken.add(site.site_id)
                continue
            attempts[site.site_id].append(result)
            if classify.needs_another_attempt(site, attempts[site.site_id], site.site_id in seen, settings.retry_attempts):
                retry.append(site)
        pending = retry

    # A missing expected_text is only believed after one more look, a little later.
    recheck = [
        site
        for site in sites
        if site.site_id not in broken and _text_missing(site, attempts[site.site_id][-1])
    ]
    confirmed_missing = set()
    if recheck:
        wait_for = settings.text_recheck_gap_seconds
        outcome = _run_text_recheck(recheck, attempts, settings, wait_for, sleep, clock)
        for site in recheck:
            second = outcome[site.site_id]
            if second is not None and _text_missing(site, second):
                confirmed_missing.add(site.site_id)

    results = {}
    for site in sites:
        site_attempts = attempts[site.site_id]
        if site.site_id in broken or not site_attempts:
            results[site.site_id] = None
            continue
        final = site_attempts[-1]
        seen_before = site.site_id in seen
        # Copies, so a result never contains itself (that would break copying and saving it).
        final.attempt_log = [replace(a) for a in site_attempts]
        final.attempts = len(site_attempts)
        final.strict = classify.is_strict(site, site_attempts, seen_before)
        final.cloudflare = any(a.cloudflare for a in site_attempts)
        final.verdict = classify.compute_verdict(site, site_attempts, seen_before, settings.retry_attempts)
        final.text_missing = site.site_id in confirmed_missing
        final.config_confirmed = classify.config_error_confirmed(site_attempts, settings.retry_attempts)
        final.note = _no_alert_note(site, final, seen_before)
        results[site.site_id] = final
    return results


def _no_alert_note(site, final, seen_before: bool) -> Optional[str]:
    """Plain-English reason shown in the table when a site gets no alert and is not clean UP."""
    signal = final.signal
    if final.verdict == classify.VERDICT_DOWN or signal in (classify.OK, *classify.INSPECTION_BLOCKED_SIGNALS):
        return None
    cloudflare_site = site.behind_cloudflare or seen_before or final.cloudflare
    if signal == classify.HTTP_ERROR:
        return f"HTTP {final.status_code}, the server answered but gave no usable page, so no alert (as before) and no content scan"
    if signal == classify.TLS_WARN:
        return "no response, certificate invalid, " + (
            "no alert because Cloudflare site" if cloudflare_site else "warning email sent"
        )
    if signal == classify.CF_CONFIG_ERROR:
        if final.config_confirmed:
            return f"Cloudflare error {final.cf_code} confirmed on all visits, warning email sent"
        return f"Cloudflare error {final.cf_code} seen but not on every visit, no alert"
    if signal in (classify.TIMEOUT, classify.OTHER_FAIL):
        return f"no response ({signal}), no alert on Cloudflare or externally monitored sites"
    return None


def _run_text_recheck(sites, attempts, settings, wait_for, sleep, clock) -> dict:
    """One extra visit for sites whose expected_text looked missing."""

    def recheck(site):
        try:
            previous = attempts[site.site_id][-1].started_at
            wait = previous + wait_for - clock()
            if wait > 0:
                sleep(wait)
            return check_once(site, settings)
        except Exception:
            log.exception("%s internal check error", settings.log_name(site))
            return None

    workers = max(1, min(len(sites), settings.max_workers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {site.site_id: pool.submit(recheck, site) for site in sites}
        return {site_id: future.result() for site_id, future in futures.items()}


def check_site(site, settings, sleep=time.sleep, clock=time.time, cloudflare_seen=False):
    """Check a single site (handy for tests and quick experiments)."""
    seen = {site.site_id} if cloudflare_seen else set()
    return run_uptime_checks([site], settings, seen, sleep, clock)[site.site_id]
