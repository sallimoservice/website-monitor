"""Uptime check. Visits a website and decides whether it is up or down."""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

import requests

log = logging.getLogger("monitor.uptime")

# A normal desktop browser, so firewalls do not treat the monitor as a bot.
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
MAX_BODY_BYTES = 2_000_000

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


def status_means_down(status_code: int, allow_auth: bool) -> bool:
    """4xx and 5xx mean down, except 401/403 for sites marked allow_auth."""
    if status_code < 400:
        return False
    return not (allow_auth and status_code in (401, 403))


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
                ok=not status_means_down(code, site.allow_auth),
                status_code=code,
                response_time=elapsed,
                final_url=response.url,
                body=_decode(bytes(body), response.encoding),
            )
            if not result.ok:
                result.error = f"Website returned HTTP {code} {response.reason or ''}".strip()
            return result
    except requests.exceptions.SSLError:
        return UptimeResult(ok=False, error="SSL error (certificate problem)")
    except requests.exceptions.Timeout:
        return UptimeResult(ok=False, error=f"Timeout (no answer within {timeout:g} seconds)")
    except requests.exceptions.TooManyRedirects:
        return UptimeResult(ok=False, error="Too many redirects (redirect loop)")
    except requests.exceptions.ConnectionError as exc:
        text = str(exc).lower()
        if any(hint in text for hint in _DNS_HINTS):
            return UptimeResult(ok=False, error="DNS lookup failed (domain not found)")
        return UptimeResult(ok=False, error="Connection failed (server refused or unreachable)")
    except requests.exceptions.RequestException as exc:
        return UptimeResult(ok=False, error=f"Request error ({type(exc).__name__})")


def check_site(site, settings, sleep=time.sleep) -> UptimeResult:
    """Check a site, retrying so one hiccup never causes a false DOWN alert.

    A site only counts as down when all attempts fail (default 3, 10 seconds apart).
    """
    result = UptimeResult(ok=False, error="Not checked")
    for attempt in range(1, settings.retry_attempts + 1):
        result = check_once(site, settings.request_timeout)
        result.attempts = attempt
        if result.ok:
            return result
        if attempt < settings.retry_attempts:
            log.info("%s attempt %d failed, retrying.", settings.log_name(site), attempt)
            sleep(settings.retry_gap_seconds)
    result.attempts = settings.retry_attempts
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
