"""Network evidence for a website: DNS (two public resolvers), TCP and TLS.

Python cannot ask a chosen DNS server a question without an extra library, so we
use the free HTTPS DNS services of Cloudflare (1.1.1.1) and Google (8.8.8.8).
A lookup that itself fails is "ERROR" or "SERVFAIL", never a DNS failure.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

RESOLVERS = (
    ("1.1.1.1", "https://cloudflare-dns.com/dns-query"),
    ("8.8.8.8", "https://dns.google/resolve"),
)
DNS_TIMEOUT_SECONDS = 5.0
# Answers that mean "this domain really has no address".
DEFINITE_DNS_FAILURES = frozenset({"NXDOMAIN", "NODATA"})


@dataclass
class Probes:
    dns: dict = field(default_factory=dict)   # {"1.1.1.1": "OK", "8.8.8.8": "OK"}
    tcp: str = "n/a"                          # ok / fail / dns_error (our own lookup failed)
    tls: str = "n/a"                          # ok / cert_invalid / fail / skipped / n/a (plain http)
    port: int = 443

    @property
    def dns_failed(self) -> bool:
        """True only if BOTH resolvers say the domain has no address."""
        return all(self.dns.get(name) in DEFINITE_DNS_FAILURES for name, _ in RESOLVERS)


def _doh_query(url: str, host: str, record_type: str) -> str:
    """One DNS question. Returns OK, NXDOMAIN, NODATA, SERVFAIL or ERROR."""
    try:
        response = requests.get(
            url,
            params={"name": host, "type": record_type},
            headers={"accept": "application/dns-json"},
            timeout=DNS_TIMEOUT_SECONDS,
        )
        data = response.json()
    except Exception:
        return "ERROR"
    status = data.get("Status")
    if status == 3:
        return "NXDOMAIN"
    if status == 2:
        return "SERVFAIL"
    if status != 0:
        return "ERROR"
    wanted_type = 1 if record_type == "A" else 28
    if any(answer.get("type") == wanted_type for answer in data.get("Answer") or []):
        return "OK"
    return "NODATA"


def _combine(answers) -> str:
    """Merge the A and AAAA answers of one resolver into a single word."""
    if "OK" in answers:
        return "OK"
    if "NXDOMAIN" in answers:
        return "NXDOMAIN"
    if all(a == "NODATA" for a in answers):
        return "NODATA"
    return "SERVFAIL" if "SERVFAIL" in answers else "ERROR"


def probe_dns(host: str) -> dict:
    """Ask both resolvers for A and AAAA records, all four questions at the same time."""
    try:
        ipaddress.ip_address(host)
        return {name: "n/a" for name, _ in RESOLVERS}   # a raw IP address needs no DNS
    except ValueError:
        pass
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            (name, rtype): pool.submit(_doh_query, url, host, rtype)
            for name, url in RESOLVERS
            for rtype in ("A", "AAAA")
        }
        return {
            name: _combine([futures[(name, "A")].result(), futures[(name, "AAAA")].result()])
            for name, _ in RESOLVERS
        }


def probe_tcp(host: str, port: int, timeout: float) -> str:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return "ok"
    except socket.gaierror:
        return "dns_error"   # the name did not resolve here: a DNS question, not a refused connection
    except OSError:
        return "fail"


def probe_tls(host: str, port: int, timeout: float) -> str:
    """Handshake with full certificate checking. cert_invalid = expired, wrong name, untrusted."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return "ok"
    except ssl.SSLCertVerificationError:
        return "cert_invalid"
    except (ssl.SSLError, OSError):
        return "fail"


def run_probes(url: str, timeout: float) -> Probes:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    https = parsed.scheme == "https"
    port = parsed.port or (443 if https else 80)
    probes = Probes(port=port, dns=probe_dns(host))
    probes.tcp = probe_tcp(host, port, timeout)
    if not https:
        probes.tls = "n/a"
    elif probes.tcp != "ok":
        probes.tls = "skipped"
    else:
        probes.tls = probe_tls(host, port, timeout)
    return probes
