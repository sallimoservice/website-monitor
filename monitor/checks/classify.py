"""Decides what one visit to a website means. Pure functions, no network access.

Every visit ("attempt") ends in exactly ONE signal. The order the signals are
checked in matters, because some situations overlap (a Cloudflare 521 page also
carries a cf-ray header, so origin errors are checked before challenges).

    1. DNS_FAIL          both 1.1.1.1 and 8.8.8.8 say the domain does not exist
    2. CONN_FAIL         the TCP connection itself fails
       TLS_WARN          the certificate is invalid or expired (never DOWN)
    3. CF_ORIGIN_ERROR   HTTP 521-526 from the Cloudflare edge (origin refused, timed out, unreachable,
                         or has a broken certificate: visitors see it too)
       CF_ORIGIN_UNKNOWN HTTP 520 from the Cloudflare edge. "Empty or unexpected answer" can be the
                         origin's firewall rejecting only OUR request while visitors are fine, so it
                         is a WARNING after 3 visits in a row and never DOWN.
    4. CF_VISITOR_BLOCK  a Cloudflare 1xxx page about the VISITOR (firewall rule, ban, rate
                         limit). Never DOWN, never an alert.
       CF_CONFIG_ERROR   a Cloudflare 1xxx page about the SITE (broken DNS or origin setup).
                         Never DOWN, but a WARNING once 3 visits in a row confirm it.
    5. CHALLENGE         Cloudflare "checking your browser" style page (never DOWN). Needs real
                         proof: the cf-mitigated header or a challenge page marker. A cf-ray header
                         plus a status code is NOT proof, Cloudflare adds cf-ray to answers it
                         merely passes through from the server behind it.
       ORIGIN_5XX        a 5xx answer passed through Cloudflare from the server behind it
                         (502, 503, 504 ...) with no challenge marker. Never DOWN, but a WARNING
                         when it is confirmed on 3 visits in a row.
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
CF_ORIGIN_UNKNOWN = "CF_ORIGIN_UNKNOWN"
CF_VISITOR_BLOCK = "CF_VISITOR_BLOCK"
CF_CONFIG_ERROR = "CF_CONFIG_ERROR"
ORIGIN_5XX = "ORIGIN_5XX"
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
# Signals that all mean "the server behind Cloudflare is in trouble". On a strict site (Cloudflare, detected
# Cloudflare, or one an external monitor watches) three visits in a row from this family give a WARNING.
# All CF_ORIGIN_ERROR is still a DOWN. A plain 5xx without Cloudflare headers counts too (see
# is_origin_trouble). A mix such as 522, then 504, then a timeout is still trouble.
ORIGIN_TROUBLE_SIGNALS = frozenset({CF_ORIGIN_ERROR, CF_ORIGIN_UNKNOWN, ORIGIN_5XX, TIMEOUT})
# Only a clean normal page may be used for content checks or saved as a baseline.
SCANNABLE_SIGNALS = frozenset({OK})

VERDICT_DOWN = "down"
VERDICT_MIXED = "mixed"          # three trustworthy failures, but not the same kind
VERDICT_NOT_DOWN = "not_down"

# 4xx answers that mean "the page is gone" count as DOWN on normal (non-Cloudflare) sites.
BROKEN_PAGE_CODES = frozenset({404, 410})

# Cloudflare 1xxx errors that are the SITE's own problem (broken DNS, origin, tunnel, Workers
# or rewrite rules). Each maps to one plain sentence for the warning email. Checked against
# Cloudflare's "1xxx errors" documentation (developers.cloudflare.com, support section).
# Every OTHER 1xxx code is treated as a visitor block (silent), for example
#   1003 direct IP access, 1005 ASN ban, 1006/1007/1008/1106 IP ban, 1009 country ban,
#   1010 browser signature ban, 1011 hotlink protection, 1012 access denied,
#   1013 hostname/SNI mismatch (caused by the visitor's browser or network),
#   1015 rate limited, 1020 firewall rule.
CF_CONFIG_ERRORS = {
    1000: "A DNS record for this site points to a prohibited IP address, so Cloudflare refuses to serve it.",
    1001: "Cloudflare cannot resolve the site's DNS, for example a CNAME that points to a domain that does not exist.",
    1002: "A DNS record for this site points to a prohibited IP address, so Cloudflare refuses to serve it.",
    1004: "Cloudflare says this host is not configured to serve web traffic (the proxy may be disabled or DNS changes have not spread yet).",
    1014: "The site uses a CNAME to a domain on a different Cloudflare account, which Cloudflare forbids by default.",
    1016: "Cloudflare cannot find the origin server because its DNS record is missing or points to a name that does not resolve.",
    1018: "Cloudflare cannot find this host, usually because the domain was just activated or a DNS provider has an outage.",
    1019: "Cloudflare reports a compute (Workers) server error for this site.",
    1023: "Cloudflare cannot find this host, usually because the domain was just activated or a DNS provider has an outage.",
    1025: "The site has reached its Cloudflare Workers plan limit, so requests are refused.",
    1033: "The Cloudflare Tunnel that connects to the origin server is broken or offline.",
    1034: "Cloudflare restricted the edge IP because the site's DNS points at 1.1.1.1 or another unsupported address.",
    1035: "A Cloudflare rewrite rule on this site is invalid (bad URI path) and is breaking requests.",
    1036: "A Cloudflare rewrite rule on this site is invalid (value too long) and is breaking requests.",
    1037: "A Cloudflare rewrite rule on this site cannot be evaluated and is breaking requests.",
    1040: "A Cloudflare rewrite rule on this site tries a header change that is not allowed and is breaking requests.",
    1041: "A Cloudflare rewrite rule on this site sets an invalid header value and is breaking requests.",
    1101: "The site's Cloudflare Worker crashed with an unhandled error.",
    1102: "The site's Cloudflare Worker used too much CPU or memory.",
    1200: "Cloudflare's queue for this site is full because too many requests are waiting.",
}

# Visitor-side 1xxx codes we know about. They stay silent. Any 1xxx code that is in neither
# this set nor CF_CONFIG_ERRORS is still silent, but is counted as "unrecognised" so the daily
# summary can mention it (see is_recognised_cf_code).
CF_VISITOR_BLOCK_CODES = frozenset({1003, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1015, 1020, 1106})

# Words that only a real challenge page carries. A plain server error page (a maintenance
# notice that says "back in just a moment", an "Attention required" banner) can contain the same
# words in its body, so the generic phrases only count when they are the page TITLE, which is how
# Cloudflare's own pages are built. "cf-chl" appears only in Cloudflare's challenge code.
CHALLENGE_TITLE_STARTS = ("just a moment", "attention required")
CHALLENGE_TEXT_MARKERS = ("cf-chl",)
# Cloudflare also puts a harmless script under /cdn-cgi/challenge-platform/ into ORDINARY pages,
# including errors passed through from the server. So that word alone proves nothing. Only a
# real challenge page also loads its "orchestrate" / "chl_page" scripts.
_CHALLENGE_PLATFORM_PROOF = ("orchestrate", "chl_page")
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
    cf_code: Optional[int] = None  # the Cloudflare 1xxx code, if one was found


def is_cloudflare(headers: dict) -> bool:
    """True if the response came through Cloudflare. `headers` has lower-case names."""
    return "cf-ray" in headers or headers.get("server", "").lower() == "cloudflare"


def is_recognised_cf_code(code) -> bool:
    return code in CF_CONFIG_ERRORS or code in CF_VISITOR_BLOCK_CODES


def find_cf_error_code(status: int, headers: dict, body: str) -> Optional[int]:
    """The Cloudflare 1xxx code on an error page (1020, 1015, 1016 ...), or None."""
    if status < 400 or not body:
        return None
    text = body[:_SCAN_LIMIT]
    if not (is_cloudflare(headers) or "cloudflare" in text.lower()):
        return None
    for pattern in _CF_ERROR_PATTERNS:
        match = pattern.search(text)
        if match:
            return int(match.group(1))
    return None


def _page_title(body: str) -> str:
    title = _TITLE_RE.search((body or "")[:20_000])
    return title.group(1).strip().lower() if title else ""


def find_challenge(status: int, headers: dict, body: str) -> Optional[str]:
    """Detect a Cloudflare challenge. Returns the name of the marker that matched.

    Proof is one of: the cf-mitigated header; on an error answer, a challenge page title or
    Cloudflare's own challenge code; on a 200, the exact "Just a moment..." title. A cf-ray header
    with a status code is deliberately NOT proof, and neither is a phrase in the body text, or an
    overloaded server's 503 would be mistaken for a challenge and go unreported.
    """
    if "cf-mitigated" in headers:
        return "header cf-mitigated"
    title = _page_title(body)
    if status == 200:
        return "title 'just a moment'" if title.startswith("just a moment") else None
    for start in CHALLENGE_TITLE_STARTS:
        if title.startswith(start):
            return f"title '{start}'"
    lowered = (body or "")[:_SCAN_LIMIT].lower()
    for marker in CHALLENGE_TEXT_MARKERS:
        if marker in lowered:
            return f"text '{marker}'"
    if "checking your browser" in lowered and "cloudflare" in lowered:
        return "text 'checking your browser' (Cloudflare page)"
    if "challenge-platform" in lowered and any(word in lowered for word in _CHALLENGE_PLATFORM_PROOF):
        return "text 'challenge-platform' (challenge page)"
    return None


def classify_response(status: int, headers: dict, body: str) -> Classification:
    """Label an attempt that got an HTTP answer."""
    if status == 520 and is_cloudflare(headers):
        return Classification(CF_ORIGIN_UNKNOWN)
    if 521 <= status <= 526 and is_cloudflare(headers):
        return Classification(CF_ORIGIN_ERROR)
    code = find_cf_error_code(status, headers, body)
    if code is not None:
        if code in CF_CONFIG_ERRORS:
            return Classification(CF_CONFIG_ERROR, f"cf-error-{code}", code)
        return Classification(CF_VISITOR_BLOCK, f"cf-error-{code}", code)
    marker = find_challenge(status, headers, body)
    if marker:
        return Classification(CHALLENGE, marker)
    if status >= 500 and is_cloudflare(headers):
        return Classification(ORIGIN_5XX)   # Cloudflare passed on an error from the server behind it
    if status >= 400:
        return Classification(HTTP_ERROR)
    return Classification(OK)


def classify_failure(kind: str, probes) -> str:
    """Label an attempt that got no HTTP answer.

    `kind` is what went wrong: "ssl_cert" (certificate rejected), "ssl" (other handshake
    problem), "timeout", "redirects", "connection" or "other".
    `probes` is the DNS/TCP/TLS evidence collected right after the failure.
    """
    if probes is not None:
        if probes.dns_failed:
            return DNS_FAIL
        if probes.tcp == "fail":
            return CONN_FAIL
    if kind == "ssl_cert":
        return TLS_WARN   # requests itself rejected the certificate, no second opinion needed
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
    if signal in (HTTP_ERROR, ORIGIN_5XX):
        return status_code is not None and (status_code >= 500 or status_code in BROKEN_PAGE_CODES)
    return False


def warns_on_origin_trouble(site, attempts, cloudflare_seen: bool) -> bool:
    """Every strict site gets the warning, including sites an external monitor watches.

    The external monitor can own the DOWN decision. It does not own this monitor's visibility.
    """
    return is_strict(site, attempts, cloudflare_seen)


def is_origin_trouble(attempt) -> bool:
    """One visit that counts as trouble from the server: a 5xx (with or without Cloudflare headers) or a timeout."""
    if attempt.signal in ORIGIN_TROUBLE_SIGNALS:
        return True
    return attempt.signal == HTTP_ERROR and attempt.status_code is not None and attempt.status_code >= 500


def origin_trouble_confirmed(site, attempts, cloudflare_seen: bool, needed: int) -> bool:
    """3 visits in a row from ORIGIN_TROUBLE_SIGNALS, not all CF_ORIGIN_ERROR (that is a DOWN)."""
    if len(attempts) < needed or not warns_on_origin_trouble(site, attempts, cloudflare_seen):
        return False
    if not all(is_origin_trouble(a) for a in attempts):
        return False
    return not all(a.signal == CF_ORIGIN_ERROR for a in attempts)


def needs_another_attempt(site, attempts, cloudflare_seen: bool, needed: int) -> bool:
    """Keep retrying only while every attempt so far could still add up to DOWN."""
    if len(attempts) >= needed:
        return False
    if all(a.signal == CF_CONFIG_ERROR for a in attempts):
        return True   # a site-side Cloudflare error is confirmed by seeing it 3 times in a row
    if warns_on_origin_trouble(site, attempts, cloudflare_seen) and all(is_origin_trouble(a) for a in attempts):
        return True   # trouble behind Cloudflare is confirmed the same way
    strict = is_strict(site, attempts, cloudflare_seen)
    if not all(down_eligible(a.signal, a.status_code, strict) for a in attempts):
        return False
    if strict and len({a.signal for a in attempts}) > 1:
        return False  # mixed kinds can never become DOWN, so do not waste time
    return True


def config_error_confirmed(attempts, needed: int) -> bool:
    """True when every one of `needed` visits showed a site-side Cloudflare error page."""
    return len(attempts) >= needed and all(a.signal == CF_CONFIG_ERROR for a in attempts)


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
