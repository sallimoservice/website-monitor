"""Uptime check. Visits a website and decides whether it is up or down."""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

import requests

log = logging.getLogger("monitor.uptime")

# Headers of a normal desktop Chrome browser, so firewalls do not treat the monitor as a bot.
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
}
MAX_BODY_BYTES = 2_000_000

# Cloudflare's "I could not get a good answer from the website's server" codes.
# These are often short hiccups or bot blocks, so they get one patient retry before we alert.
CLOUDFLARE_CODES = {520, 521, 522, 523, 524}

_DNS_HINTS = (
    "name or service not known",
    "nodename nor servname",
    "getaddrinfo failed",
    "temporary failure in name resolution",
    "nameresolutionerror",
    "no address associated",
)


@dataclass
class UptimeResult:
    ok: bool
    status_code: Optional[int] = None
    response_time: Optional[float] = None   # seconds
    error: Optional[str] = None             # plain-English reason when not ok
    attempts: int = 1
    final_url: Optional[str] = None         # where we ended up after redirects
    body: Optional[str] = None              # page HTML, reused by the security checks
    note: Optional[str] = None              # extra remark for the log (never changes up/down)
    # What kind of failure it was: http, timeout, dns, ssl, connection, redirects or request.
    error_kind: Optional[str] = None


# 4xx codes that mean "the page is gone", so they are a real problem for a client homepage.
BROKEN_PAGE_CODES = {404, 410}


def status_means_down(status_code: int) -> bool:
    """5xx, 404 and 410 mean down.

    2xx and 3xx are fine. The other 4xx codes (401, 403, 405, 429 ...) mean the server
    answered and is only refusing or blocking the monitor, so the site is counted as UP.
    """
    return status_code >= 500 or status_code in BROKEN_PAGE_CODES


def _decode(raw: bytes, encoding: Optional[str]) -> str:
    try:
        return raw.decode(encoding or "utf-8", errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def check_once(site, timeout: float) -> UptimeResult:
    """One single visit to the site. Never raises; failures come back as a result."""
    started = time.perf_counter()
    try:
        with requests.get(
            site.url, headers=HEADERS, timeout=timeout, allow_redirects=True, stream=True
        ) as response:
            body = bytearray()
            for chunk in response.iter_content(65536):
                body.extend(chunk)
                if len(body) >= MAX_BODY_BYTES:
                    break
                # Total time limit, so a server that sends one byte at a time cannot stall us.
                if time.perf_counter() - started > timeout * 2:
                    raise requests.exceptions.ReadTimeout()
            elapsed = time.perf_counter() - started
            code = response.status_code
            result = UptimeResult(
                ok=not status_means_down(code),
                status_code=code,
                response_time=elapsed,
                final_url=response.url,
                body=_decode(bytes(body), response.encoding),
            )
            if not result.ok:
                result.error_kind = "http"
                result.error = f"Website returned HTTP {code} {response.reason or ''}".strip()
                if code in CLOUDFLARE_CODES:
                    result.error += " (Cloudflare could not get a good answer from the server)"
            elif 400 <= code < 500:
                result.note = "server answered so it counts as UP, but it may be blocking the monitor"
            return result
    except requests.exceptions.SSLError:
        return UptimeResult(ok=False, error_kind="ssl", error="SSL error (certificate problem)")
    except requests.exceptions.Timeout:
        return UptimeResult(
            ok=False, error_kind="timeout", error=f"Timeout (no answer within {timeout:g} seconds)"
        )
    except requests.exceptions.TooManyRedirects:
        return UptimeResult(ok=False, error_kind="redirects", error="Too many redirects (redirect loop)")
    except requests.exceptions.ConnectionError as exc:
        text = str(exc).lower()
        if any(hint in text for hint in _DNS_HINTS):
            return UptimeResult(ok=False, error_kind="dns", error="DNS lookup failed (domain not found)")
        return UptimeResult(
            ok=False, error_kind="connection", error="Connection failed (server refused or unreachable)"
        )
    except requests.exceptions.RequestException as exc:
        return UptimeResult(ok=False, error_kind="request", error=f"Request error ({type(exc).__name__})")


def check_site(site, settings, sleep=time.sleep) -> UptimeResult:
    """Check a site, retrying so one hiccup never causes a false DOWN alert.

    A site only counts as down when all attempts fail (4 attempts, 15 seconds apart).
    A Cloudflare 520-524 error gets ONE extra retry after 30 seconds. If that retry
    fails with a Cloudflare error too, we alert straight away.
    """
    result = UptimeResult(ok=False, error="Not checked")
    cloudflare_retry_used = False
    for attempt in range(1, settings.retry_attempts + 1):
        result = check_once(site, settings.request_timeout)
        result.attempts = attempt
        if result.ok:
            return result
        if attempt == settings.retry_attempts:
            break
        if result.status_code in CLOUDFLARE_CODES:
            if cloudflare_retry_used:
                break
            cloudflare_retry_used = True
            gap = settings.cloudflare_retry_gap_seconds
        else:
            gap = settings.retry_gap_seconds
        log.info("%s attempt %d failed, retrying in %gs.", settings.log_name(site), attempt, gap)
        sleep(gap)
    return result


def run_uptime_checks(sites, settings) -> dict:
    """Check every site at the same time. Returns {site_id: UptimeResult or None}.

    None means our own code failed for that site. We never turn that into a DOWN
    alert, because the website itself may be perfectly fine.
    """
    results = {}
    workers = max(1, min(len(sites), settings.max_workers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {site.site_id: pool.submit(check_site, site, settings) for site in sites}
        for site in sites:
            try:
                results[site.site_id] = futures[site.site_id].result()
            except Exception:
                log.exception("%s internal check error", settings.log_name(site))
                results[site.site_id] = None
    return results
