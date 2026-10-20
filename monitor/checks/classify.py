"""Decides what one visit to a website means. Pure functions, no network access.

Every visit ("attempt") ends in exactly ONE signal. The order the signals are
checked in matters, because some situations overlap (a Cloudflare 521 page also
carries a cf-ray header, so origin errors are checked before challenges).

    1. DNS_FAIL          both 1.1.1.1 and 8.8.8.8 say the domain does not exist
    2. CONN_FAIL         the TCP connection itself fails
       TLS_WARN          the certificate is invalid or expired (never DOWN)
    3. CF_ORIGIN_ERROR   HTTP 520-526 from the Cloudflare edge
    4. CF_VISITOR_BLOCK  a Cloudflare 1xxx error page (never DOWN)
    5. CHALLENGE         Cloudflare "checking your browser" style page (never DOWN)
    6. TIMEOUT           no answer within the time limit
       OTHER_FAIL        any other connection problem (redirect loop, reset ...)
    7. HTTP_ERROR        any other 4xx or 5xx answer
    8. OK                a normal page
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

DNS_FAIL = "DNS_FAIL"
CONN_FAIL = "CONN_FAIL"
TLS_WARN = "TLS_WARN"
CF_ORIGIN_ERROR = "CF_ORIGIN_ERROR"
CF_VISITOR_BLOCK = "CF_VISITOR_BLOCK"
CHALLENGE = "CHALLENGE"
TIMEOUT = "TIMEOUT"
OTHER_FAIL = "OTHER_FAIL"
HTTP_ERROR = "HTTP_ERROR"
OK = "OK"

# The only signals that can make a Cloudflare or externally monitored site DOWN.
STRICT_DOWN_SIGNALS = frozenset({DNS_FAIL, CONN_FAIL, CF_ORIGIN_ERROR})
# Cloudflare answered, but with a page meant to stop visitors or bots. We cannot look
# inside the real site, and we say nothing about it.
INSPECTION_BLOCKED_SIGNALS = frozenset({CHALLENGE, CF_VISITOR_BLOCK})
# Only a clean normal page may be used for content checks or saved as a baseline.
SCANNABLE_SIGNALS = frozenset({OK})

VERDICT_DOWN = "down"
VERDICT_MIXED = "mixed"          # three trustworthy failures, but not the same kind
VERDICT_NOT_DOWN = "not_down"

# 4xx answers that mean "the page is gone" count as DOWN on normal (non-Cloudflare) sites.
BROKEN_PAGE_CODES = frozenset({404, 410})

CHALLENGE_TEXT_MARKERS = (
    "just a moment",
    "attention required",
    "cf-chl",
    "challenge-platform",
    "checking your browser",
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CF_ERROR_PATTERNS = (
    re.compile(r"cf-error-code[^>]*>\s*(1\d{3})\s*<", re.IGNORECASE),
    re.compile(r"error\s*code\s*:?\s*(1\d{3})\b", re.IGNORECASE),
    re.compile(r"\berror\s+(1\d{3})\b", re.IGNORECASE),
)
_SCAN_LIMIT = 200_000  # characters of a page we look at when hunting for markers


@dataclass(frozen=True)
class Classification:
    signal: str
    marker: Optional[str] = None   # name of what matched (never the page itself)


def is_cloudflare(headers: dict) -> bool:
    """True if the response came through Cloudflare. `headers` has lower-case names."""
    return "cf-ray" in headers or headers.get("server", "").lower() == "cloudflare"


def find_visitor_block(status: int, headers: dict, body: str) -> Optional[str]:
    """Cloudflare 1xxx error pages (1020, 1015, 1010 ...). Only looked for on error answers."""
    if status < 400 or not body:
        return None
    text = body[:_SCAN_LIMIT]
    if not (is_cloudflare(headers) or "cloudflare" in text.lower()):
        return None
    for pattern in _CF_ERROR_PATTERNS:
        match = pattern.search(text)
        if match:
            return f"cf-error-{match.group(1)}"
    return None


def find_challenge(status: int, headers: dict, body: str) -> Optional[str]:
    """Detect a Cloudflare challenge. Returns the name of the marker that matched.

    Words like "challenge-platform" sit inside the ordinary 200 pages of many protected
    sites, so text markers only count on error answers. On a 200 only the exact
    "Just a moment..." page title counts.
    """
    if "cf-mitigated" in headers:
        return "header cf-mitigated"
    if "cf-ray" in headers and status in (403, 429, 503):
        return f"cf-ray with HTTP {status}"
    if status != 200:
        lowered = (body or "")[:_SCAN_LIMIT].lower()
        for marker in CHALLENGE_TEXT_MARKERS:
            if marker in lowered:
                return f"text '{marker}'"
        return None
    title = _TITLE_RE.search((body or "")[:20_000])
    if title and title.group(1).strip().lower().startswith("just a moment"):
        return "title 'just a moment'"
    return None


def classify_response(status: int, headers: dict, body: str) -> Classification:
    """Label an attempt that got an HTTP answer."""
    if 520 <= status <= 526 and is_cloudflare(headers):
        return Classification(CF_ORIGIN_ERROR)
    marker = find_visitor_block(status, headers, body)
    if marker:
        return Classification(CF_VISITOR_BLOCK, marker)
    marker = find_challenge(status, headers, body)
    if marker:
        return Classification(CHALLENGE, marker)
    if status >= 400:
        return Classification(HTTP_ERROR)
    return Classification(OK)


def classify_failure(kind: str, probes) -> str:
    """Label an attempt that got no HTTP answer.

    `kind` is what went wrong: "ssl", "timeout", "redirects", "connection" or "other".
    `probes` is the DNS/TCP/TLS evidence collected right after the failure.
    """
    if probes is not None:
        if probes.dns_failed:
            return DNS_FAIL
        if probes.tcp == "fail":
            return CONN_FAIL
    if kind == "ssl":
        if probes is not None and probes.tls == "cert_invalid":
            return TLS_WARN
        return OTHER_FAIL
    if kind == "timeout":
        return TIMEOUT
    return OTHER_FAIL


def page_is_scannable(signal: str, status_code: Optional[int]) -> bool:
    return signal in SCANNABLE_SIGNALS and status_code == 200


def is_strict(site, attempts, cloudflare_seen: bool) -> bool:
    """Strict rules apply to Cloudflare sites (flagged or detected) and externally monitored sites."""
    return bool(
        site.behind_cloudflare
        or site.uptime_source == "external"
        or cloudflare_seen
        or any(a.cloudflare for a in attempts)
    )


def down_eligible(signal: str, status_code: Optional[int], strict: bool) -> bool:
    """Can this attempt count towards DOWN?

    Strict sites: only DNS_FAIL, CONN_FAIL and CF_ORIGIN_ERROR.
    Normal sites keep the classic signals too: timeouts, 5xx, 404 and 410.
    A 401, 403, 405 or 429 on a normal site means the server answered, so it is not DOWN.
    """
    if signal in STRICT_DOWN_SIGNALS:
        return True
    if strict:
        return False
    if signal in (TIMEOUT, OTHER_FAIL):
        return True
    if signal == HTTP_ERROR:
        return status_code is not None and (status_code >= 500 or status_code in BROKEN_PAGE_CODES)
    return False


def needs_another_attempt(site, attempts, cloudflare_seen: bool, needed: int) -> bool:
    """Keep retrying only while every attempt so far could still add up to DOWN."""
    if len(attempts) >= needed:
        return False
    strict = is_strict(site, attempts, cloudflare_seen)
    if not all(down_eligible(a.signal, a.status_code, strict) for a in attempts):
        return False
    if strict and len({a.signal for a in attempts}) > 1:
        return False  # mixed kinds can never become DOWN, so do not waste time
    return True


def compute_verdict(site, attempts, cloudflare_seen: bool, needed: int) -> str:
    """DOWN needs `needed` attempts that all count towards DOWN.

    On strict sites they must also all be the same kind of failure. If the kinds are
    mixed we stay silent this run and look again next run.
    """
    strict = is_strict(site, attempts, cloudflare_seen)
    if not attempts or not all(down_eligible(a.signal, a.status_code, strict) for a in attempts):
        return VERDICT_NOT_DOWN
    if strict and len({a.signal for a in attempts}) > 1:
        return VERDICT_MIXED
    return VERDICT_DOWN if len(attempts) >= needed else VERDICT_NOT_DOWN
