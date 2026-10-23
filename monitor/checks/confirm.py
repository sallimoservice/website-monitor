"""Independent confirmation that a website is really down.

The GitHub runner is ONE viewpoint. A failure seen only from there can mean the site is down, or that
the host blocks the runner's address. So a would-be DOWN is only sent after other locations, outside
GitHub, agree. The first source is Globalping (free, no sign-up needed). Other sources can be added by
writing one more class with the same two members as `ConfirmationSource` below.

How one failing site is judged
  Round 1  ask about 5 locations spread over the world, right away.
           the runner alone fails            -> RUNNER_BLOCKED (a low-priority warning, never DOWN)
           the answer is unclear             -> UNCONFIRMED    (a warning, never DOWN)
           most locations fail too           -> wait a few minutes, then round 2
  Round 2  the runner visits again and the outside check is repeated.
           the runner now succeeds, or the outside check clears -> BLIP (no email)
           still failing in both places                         -> CONFIRMED_DOWN
           the answer is unclear                                -> UNCONFIRMED

A probe counts as failing when it gets no answer, a 5xx, a 404 or a 410. A probe that is itself
offline or broke inside Globalping is left out. A verdict needs at least 3 answering probes and a
strict majority.

Only sites that already failed on the runner are sent out (just the host name and path, never a query
string, a password or any secret). Healthy sites are never sent. Globalping measurements are public, so
nothing but a public site address goes into them.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import Optional
from urllib.parse import urlparse

import requests

from . import classify
from ..timeutil import fmt_time, fmt_utc

log = logging.getLogger("monitor.confirm")

API_URL = "https://api.globalping.io/v1"
USER_AGENT = "website-monitor/1.0 (+https://github.com/sallimoservice/website-monitor)"

# What happened to one site after the runner saw it fail.
OUTCOME_CONFIRMED_DOWN = "confirmed_down"     # failing from the runner and from most outside locations, twice
OUTCOME_RUNNER_BLOCKED = "runner_blocked"     # failing from the runner only
OUTCOME_BLIP = "blip"                         # it failed once and cleared
OUTCOME_UNCONFIRMED = "unconfirmed"           # the outside check could not give a clear answer
OUTCOME_MASS_FAILURE = "mass_failure"         # too many sites failed at once to be a site problem

VERDICT_DOWN = "down"
VERDICT_UP = "up"
VERDICT_UNCLEAR = "unclear"

PROBE_FAILING = "failing"
PROBE_REACHABLE = "reachable"
PROBE_NO_ANSWER = "no_answer"     # probe offline, or it broke on its own side: says nothing about the site

MIN_ANSWERING = 3           # a verdict needs at least this many probes that answered
MAX_SITES_PER_RUN = 5       # most sites that are sent for an outside check in one run (keeps well inside the free limit)
MASS_FAILURE_THRESHOLD = 8  # this many new failures at the same moment is treated as a problem on the monitor's side
PROBES_PER_ROUND = 5
# Spread over the world. A per-location limit is the documented way to get a fixed mix of probes.
LOCATIONS = ({"continent": "EU", "limit": 2}, {"continent": "NA", "limit": 2}, {"continent": "AS", "limit": 1})
DEFAULT_PROBE_TIMEOUT = 20           # seconds each probe may take (the API allows 5 to 30)
POLL_SECONDS = 1.0                   # the API asks for at least 0.5 seconds between reads
EXTRA_WAIT_SECONDS = 15              # the API asks clients to allow 10+ seconds on top of the probe timeout


@dataclass
class ProbeResult:
    location: str = ""      # "Frankfurt, DE"
    network: str = ""       # "Hetzner Online GmbH (AS24940)"
    kind: str = ""          # "datacenter" or "eyeball" (a home or office network) or ""
    outcome: str = PROBE_NO_ANSWER
    detail: str = ""        # "HTTP 200 in 312 ms", "no answer: connect ECONNREFUSED"


@dataclass
class Confirmation:
    """One question to one source: what each location saw, and what that adds up to."""

    source: str
    ok: bool = False                     # the source gave an answer we could read
    verdict: str = VERDICT_UNCLEAR
    reason: str = ""                     # plain-English reason, always filled in
    probes: list = field(default_factory=list)
    measurement_id: str = ""
    measurement_url: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0


@dataclass
class ConfirmRound:
    number: int
    runner_note: str = ""                # what the runner saw in this round
    runner_failing: bool = True
    confirmations: list = field(default_factory=list)   # one per source that was asked

    @property
    def decisive(self) -> Optional[Confirmation]:
        return self.confirmations[-1] if self.confirmations else None


@dataclass
class ConfirmOutcome:
    outcome: str
    reason: str
    rounds: list = field(default_factory=list)
    runner_ip: str = ""
    decided_at: float = 0.0


@dataclass
class ConfirmationRun:
    outcomes: dict = field(default_factory=dict)       # site_id -> ConfirmOutcome
    replaced: dict = field(default_factory=dict)       # site_id -> runner result that replaces the failing one
    mass_failure: list = field(default_factory=list)   # sites, when too many failed at once
    runner_ip: str = ""


class ConfirmationSource:
    """What a confirmation source must provide. Globalping below is the first one.

    name   a short label used in alerts
    check  (site, runner_result) -> Confirmation. It must never raise. When it cannot give a clear
           answer it returns verdict VERDICT_UNCLEAR with a reason.
    """

    name = "source"

    def check(self, site, runner_result) -> Confirmation:  # pragma: no cover - interface only
        raise NotImplementedError


# ----------------------------------------------------------------------------------------------
# Judging probes (pure functions, no network)
# ----------------------------------------------------------------------------------------------
def _text(value, limit=120) -> str:
    return " ".join(str(value or "").split())[:limit]


def _number(value) -> Optional[float]:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _lower_headers(headers) -> dict:
    if not isinstance(headers, dict):
        return {}
    flat = {}
    for name, value in headers.items():
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        flat[str(name).lower()] = str(value)
    return flat


def judge(probes) -> tuple:
    """Add up the probes. Returns (verdict, reason)."""
    answering = [p for p in probes if p.outcome != PROBE_NO_ANSWER]
    failing = sum(1 for p in answering if p.outcome == PROBE_FAILING)
    reachable = len(answering) - failing
    if len(answering) < MIN_ANSWERING:
        return VERDICT_UNCLEAR, (
            f"only {len(answering)} of {len(probes)} outside locations answered (at least {MIN_ANSWERING} are needed)"
        )
    if failing * 2 > len(answering):
        return VERDICT_DOWN, f"{failing} of {len(answering)} outside locations could not load the site"
    if reachable * 2 > len(answering):
        return VERDICT_UP, f"{reachable} of {len(answering)} outside locations loaded the site"
    return VERDICT_UNCLEAR, f"the outside locations are split ({failing} failing, {reachable} reachable)"


def classify_probe(item) -> ProbeResult:
    """One entry of a Globalping result list -> what that location saw. Anything odd counts as no answer."""
    probe = ProbeResult()
    if not isinstance(item, dict):
        probe.detail = "unreadable result"
        return probe
    where = item.get("probe") if isinstance(item.get("probe"), dict) else {}
    city, country = _text(where.get("city"), 40), _text(where.get("country"), 4)
    probe.location = ", ".join(part for part in (city, country) if part) or "unknown location"
    network, asn = _text(where.get("network"), 50), where.get("asn")
    probe.network = (network + (f" (AS{asn})" if isinstance(asn, int) else "")).strip()
    tags = where.get("tags") if isinstance(where.get("tags"), list) else []
    probe.kind = "datacenter" if "datacenter-network" in tags else ("eyeball" if "eyeball-network" in tags else "")

    result = item.get("result") if isinstance(item.get("result"), dict) else {}
    status = result.get("status")
    if status == "finished":
        code = result.get("statusCode")
        if not isinstance(code, int) or isinstance(code, bool):
            probe.detail = "finished without a status code"
            return probe
        verdict = classify.classify_response(code, _lower_headers(result.get("headers")), str(result.get("rawBody") or ""))
        broken = verdict.signal in (
            classify.CF_ORIGIN_ERROR, classify.CF_ORIGIN_UNKNOWN, classify.ORIGIN_5XX, classify.CF_CONFIG_ERROR,
        ) or (verdict.signal == classify.HTTP_ERROR and (code >= 500 or code in classify.BROKEN_PAGE_CODES))
        timings = result.get("timings") if isinstance(result.get("timings"), dict) else {}
        total = _number(timings.get("total"))
        probe.detail = f"HTTP {code}" + (f" in {total:.0f} ms" if total is not None else "")
        if verdict.signal in classify.INSPECTION_BLOCKED_SIGNALS:
            probe.detail += " (a security check page, so the site is answering)"
        probe.outcome = PROBE_FAILING if broken else PROBE_REACHABLE
        return probe
    if status == "failed":
        source = result.get("failureSource")
        reason = _text(result.get("rawOutput"), 90) or "no details"
        if source in ("internal", "resolver"):
            probe.detail = f"left out: the probe itself failed ({source})"
            return probe
        probe.detail = f"no answer: {reason}"
        probe.outcome = PROBE_FAILING
        return probe
    probe.detail = f"left out: probe status {_text(status, 20) or 'missing'}"
    return probe


# ----------------------------------------------------------------------------------------------
# Globalping
# ----------------------------------------------------------------------------------------------
def build_request_body(site, timeout: int = DEFAULT_PROBE_TIMEOUT) -> dict:
    """The measurement request for one failing site. Only host and path leave this machine."""
    parsed = urlparse(site.url)
    host = parsed.hostname
    if not host:
        raise ValueError("the site address has no host name")
    https = parsed.scheme == "https"
    options = {
        "request": {"method": "GET", "path": parsed.path or "/"},   # no query string: it could hold a secret
        "protocol": "HTTPS" if https else "HTTP",
    }
    port = parsed.port
    if port and port != (443 if https else 80):
        options["port"] = port
    return {
        "type": "http",
        "target": host,
        "inProgressUpdates": False,
        "locations": [dict(location) for location in LOCATIONS],
        "timeout": max(5, min(30, int(timeout))),
        "measurementOptions": options,
    }


class GlobalpingSource(ConfirmationSource):
    """Globalping (globalping.io): a free, public network of probes. Works without a token.

    The free limit without a token is 250 tests per hour per IP address, and every probe is one test.
    A token (GLOBALPING_TOKEN, free to create) raises it to 500. The limits are never worked around:
    when Globalping says the limit is used up, no check is made and the answer is "unclear".
    """

    name = "Globalping"

    def __init__(self, token: str = "", base_url: str = API_URL, sleep=time.sleep, clock=time.monotonic,
                 deadline_seconds: Optional[float] = None):
        self.token = token
        self.base_url = base_url.rstrip("/")
        self._sleep = sleep
        self._clock = clock
        self._deadline = deadline_seconds
        self._lock = threading.Lock()
        self.remaining: Optional[int] = None      # free tests left, from the last response
        self.resets_in: Optional[int] = None

    # -- public ------------------------------------------------------------------------------
    def check(self, site, runner_result=None) -> Confirmation:
        started = time.time()
        try:
            confirmation = self._check(site, started)
        except Exception as exc:   # a problem here must never become a DOWN, or a crash
            log.warning("Globalping check failed unexpectedly (%s).", type(exc).__name__)
            confirmation = self._unclear(f"unexpected error ({type(exc).__name__})", started)
        confirmation.finished_at = time.time()
        return confirmation

    # -- internals ---------------------------------------------------------------------------
    def _unclear(self, reason: str, started: float, **extra) -> Confirmation:
        return Confirmation(source=self.name, ok=False, verdict=VERDICT_UNCLEAR, reason=reason, started_at=started, **extra)

    def _headers(self) -> dict:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _note_limits(self, response) -> None:
        def whole(name):
            try:
                return int(response.headers.get(name))
            except (TypeError, ValueError):
                return None

        remaining, resets = whole("X-RateLimit-Remaining"), whole("X-RateLimit-Reset")
        with self._lock:
            if remaining is not None:
                self.remaining = remaining
            if resets is not None:
                self.resets_in = resets

    def _limit_reason(self) -> str:
        wait = f", resets in about {max(1, round((self.resets_in or 0) / 60))} min" if self.resets_in else ""
        return f"Globalping's free limit is used up{wait}"

    def _check(self, site, started: float) -> Confirmation:
        probe_timeout = DEFAULT_PROBE_TIMEOUT
        if getattr(site, "read_timeout_seconds", None):
            probe_timeout = min(30, int(site.read_timeout_seconds))
        try:
            body = build_request_body(site, probe_timeout)
        except ValueError as exc:
            return self._unclear(str(exc), started)
        with self._lock:
            if self.remaining is not None and self.remaining < PROBES_PER_ROUND:
                return self._unclear(self._limit_reason() + ", so no check was made", started)

        try:
            response = self._post(body)
        except requests.RequestException as exc:
            return self._unclear(f"could not reach Globalping ({type(exc).__name__})", started)
        if response.status_code == 429:
            return self._unclear(self._limit_reason(), started)
        if response.status_code != 202:
            return self._unclear(f"Globalping refused the request (HTTP {response.status_code})", started)
        try:
            measurement_id = response.json().get("id")
        except (ValueError, AttributeError):
            measurement_id = None
        if not isinstance(measurement_id, str) or not measurement_id:
            return self._unclear("Globalping gave an unreadable answer", started)
        url = f"{self.base_url}/measurements/{measurement_id}"

        deadline = self._clock() + (self._deadline if self._deadline is not None else probe_timeout + EXTRA_WAIT_SECONDS)
        data = None
        while True:
            self._sleep(POLL_SECONDS)
            try:
                reply = requests.get(url, headers=self._headers(), timeout=(10, 20))
            except requests.RequestException as exc:
                return self._unclear(f"could not read the result ({type(exc).__name__})", started,
                                     measurement_id=measurement_id, measurement_url=url)
            self._note_limits(reply)
            if reply.status_code == 429:
                return self._unclear(self._limit_reason(), started, measurement_id=measurement_id, measurement_url=url)
            if reply.status_code != 200:
                return self._unclear(f"Globalping could not return the result (HTTP {reply.status_code})", started,
                                     measurement_id=measurement_id, measurement_url=url)
            try:
                data = reply.json()
            except ValueError:
                return self._unclear("Globalping gave an unreadable result", started, measurement_id=measurement_id,
                                     measurement_url=url)
            if not isinstance(data, dict):
                return self._unclear("Globalping gave an unreadable result", started, measurement_id=measurement_id,
                                     measurement_url=url)
            if data.get("status") != "in-progress":
                break
            if self._clock() >= deadline:
                return self._unclear("Globalping did not finish in time", started, measurement_id=measurement_id,
                                     measurement_url=url)

        results = data.get("results")
        if data.get("status") != "finished" or not isinstance(results, list):
            return self._unclear("Globalping gave an unreadable result", started, measurement_id=measurement_id,
                                 measurement_url=url)
        probes = [classify_probe(item) for item in results]
        verdict, reason = judge(probes)
        return Confirmation(source=self.name, ok=True, verdict=verdict, reason=reason, probes=probes,
                            measurement_id=measurement_id, measurement_url=url, started_at=started)

    def _post(self, body):
        url = f"{self.base_url}/measurements"
        for attempt in (1, 2):
            response = requests.post(url, json=body, headers=self._headers(), timeout=(10, 20))
            self._note_limits(response)
            if response.status_code >= 500 and attempt == 1:
                self._sleep(2)    # one more try after a server hiccup, then give up
                continue
            return response
        return response  # pragma: no cover

    # -- --test-confirm ----------------------------------------------------------------------
    def self_test(self, host: str) -> tuple:
        """One live measurement for --test-confirm. Returns (ok, report lines): the shape of the raw answer."""
        lines = []
        body = build_request_body(_AddressOnly(f"https://{host}/"))
        lines.append(f"Request sent to {self.base_url}/measurements (token {'used' if self.token else 'not used'}):")
        lines.append(f"  {body}")
        try:
            response = self._post(body)
        except requests.RequestException as exc:
            return False, lines + [f"Could not reach Globalping: {type(exc).__name__}"]
        lines.append(f"POST answered HTTP {response.status_code}. Rate-limit headers: "
                     f"limit={response.headers.get('X-RateLimit-Limit')} consumed={response.headers.get('X-RateLimit-Consumed')} "
                     f"remaining={response.headers.get('X-RateLimit-Remaining')} reset={response.headers.get('X-RateLimit-Reset')} "
                     f"cost={response.headers.get('X-Request-Cost')}")
        lines.append(f"POST body: {_text(response.text, 300)}")
        if response.status_code != 202:
            return False, lines
        measurement_id = response.json().get("id")
        deadline = self._clock() + DEFAULT_PROBE_TIMEOUT + EXTRA_WAIT_SECONDS
        data = None
        while True:
            self._sleep(POLL_SECONDS)
            reply = requests.get(f"{self.base_url}/measurements/{measurement_id}", headers=self._headers(), timeout=(10, 20))
            data = reply.json() if reply.status_code == 200 else None
            if not isinstance(data, dict) or data.get("status") != "in-progress" or self._clock() >= deadline:
                break
        if not isinstance(data, dict):
            return False, lines + ["The result could not be read."]
        lines.append(f"Measurement {measurement_id}: top-level keys {sorted(data)}; status={data.get('status')}; "
                     f"probesCount={data.get('probesCount')}")
        results = data.get("results") if isinstance(data.get("results"), list) else []
        for number, item in enumerate(results[:2], start=1):
            if isinstance(item, dict):
                probe, result = item.get("probe") or {}, item.get("result") or {}
                lines.append(f"  result {number}: keys {sorted(item)}")
                lines.append(f"    probe keys {sorted(probe)}  tags={probe.get('tags')}")
                lines.append(f"    result keys {sorted(result)}  status={result.get('status')} statusCode={result.get('statusCode')} "
                             f"failureSource={result.get('failureSource')}")
                shape = {k: type(v).__name__ for k, v in result.items() if k not in ("rawBody", "rawHeaders")}
                lines.append(f"    result field types: {shape}")
        probes = [classify_probe(item) for item in results]
        verdict, reason = judge(probes)
        lines.append("How this program reads them:")
        for probe in probes:
            lines.append(f"  {probe.location:<28} {probe.network[:40]:<42} {probe.kind or '-':<10} {probe.outcome:<10} {probe.detail}")
        lines.append(f"Verdict: {verdict} ({reason})")
        return bool(probes), lines


class _AddressOnly:
    """Just enough of a site for build_request_body."""

    def __init__(self, url):
        self.url = url
        self.read_timeout_seconds = None


# ----------------------------------------------------------------------------------------------
# The runner's own address
# ----------------------------------------------------------------------------------------------
_runner_ip_cache: Optional[str] = None


def lookup_runner_ip(timeout: float = 8.0) -> str:
    """The public address this machine is seen from, or "" if it cannot be found. Cached per run."""
    global _runner_ip_cache
    if _runner_ip_cache is not None:
        return _runner_ip_cache
    found = ""
    for url, key in (("https://1.1.1.1/cdn-cgi/trace", "ip="), ("https://api.ipify.org", "")):
        try:
            text = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT}).text
        except requests.RequestException:
            continue
        candidate = ""
        for line in text.splitlines():
            line = line.strip()
            if key and line.startswith(key):
                candidate = line[len(key):].strip()
            elif not key and line:
                candidate = line
        try:
            found = str(ipaddress.ip_address(candidate))
            break
        except ValueError:
            continue
    _runner_ip_cache = found
    return found


def build_sources(settings) -> list:
    """The confirmation sources in the order they are asked. Add new sources here."""
    return [GlobalpingSource(token=settings.globalping_token, base_url=settings.globalping_url)]


# ----------------------------------------------------------------------------------------------
# The decision
# ----------------------------------------------------------------------------------------------
def ask_sources(sources, site, runner_result) -> list:
    """Ask the sources in order until one gives a clear answer. Returns what each one said."""
    answers = []
    for source in sources:
        try:
            answer = source.check(site, runner_result)
        except Exception as exc:   # a source that raises is a source that could not answer
            answer = Confirmation(source=getattr(source, "name", "source"), reason=f"unexpected error ({type(exc).__name__})")
        answers.append(answer)
        if answer.verdict != VERDICT_UNCLEAR:
            break
    if not answers:
        answers.append(Confirmation(source="none", reason="no confirmation source is configured"))
    return answers


def merge_runner_result(previous, newer):
    """The runner checked again. The newer result stands, and it carries the visits of both rounds."""
    merged = replace(newer)
    merged.attempt_log = list(previous.attempt_log or [previous]) + list(newer.attempt_log or [newer])
    merged.attempts = len(merged.attempt_log)
    merged.requests_made = previous.requests_made + newer.requests_made
    merged.cloudflare = previous.cloudflare or newer.cloudflare
    return merged


def is_candidate(site, result, already_down: bool) -> bool:
    """Does this runner result need an outside opinion before it can become DOWN?"""
    if result is None or result.verdict != classify.VERDICT_DOWN:
        return False
    if result.signal == classify.DNS_FAIL:
        return False      # two public resolvers outside GitHub already agree
    if site.connection_refused_is_warning and result.signal == classify.CONN_FAIL and not already_down:
        return False      # this site's own setting says a refused connection is only a warning
    return True


def _reasons(confirmations) -> str:
    return "; ".join(f"{c.source}: {c.reason}" for c in confirmations if c.reason)


def _describe(result) -> str:
    return f"{result.signal}" + (f" (HTTP {result.status_code})" if result.status_code else "")


def run_confirmation(sites, results, settings, sources, already_down=lambda site: False, recheck=None,
                     sleep=None, clock=time.time, ip_lookup=None,
                     max_sites=MAX_SITES_PER_RUN, mass_threshold=MASS_FAILURE_THRESHOLD) -> ConfirmationRun:
    """Decide, for every site that failed on the runner, whether it is really down. Never raises on a bad answer.

    `results` is {site_id: the runner's final result}. `recheck(sites)` repeats the runner's own check for
    those sites and returns {site_id: result or None}.
    """
    sleep = sleep or time.sleep
    ip_lookup = ip_lookup or lookup_runner_ip
    run = ConfirmationRun()
    candidates = [s for s in sites if is_candidate(s, results.get(s.site_id), already_down(s))]
    if not candidates:
        return run
    if recheck is None:
        from .uptime import run_uptime_checks   # imported here: uptime does not import this module

        def recheck(again_sites):
            return run_uptime_checks(again_sites, settings)

    run.runner_ip = _safe_ip(ip_lookup)
    known = [s for s in candidates if already_down(s)]      # outages that were confirmed on an earlier run
    new = [s for s in candidates if not already_down(s)]

    def decide(site, outcome, reason, rounds):
        run.outcomes[site.site_id] = ConfirmOutcome(outcome, reason, rounds, run.runner_ip, clock())

    if len(new) >= mass_threshold:
        # Many sites failing at the same moment is far more likely to be the runner or its network than
        # that many separate outages. One warning is sent for all of them, and no DOWN.
        run.mass_failure = list(new)
        for site in new:
            decide(site, OUTCOME_MASS_FAILURE,
                   f"{len(new)} sites failed at the same time, so this looks like a problem with the monitor's own connection", [])
        new = []
    over_cap = new[max_sites:]
    new = new[:max_sites]
    for site in over_cap:
        decide(site, OUTCOME_UNCONFIRMED,
               f"not checked from outside this run (at most {max_sites} sites are checked per run). It is tried again next run", [])

    def round_one(site):
        rnd = ConfirmRound(1, runner_note=f"{_describe(results[site.site_id])} on all {results[site.site_id].attempts} visits")
        rnd.confirmations = ask_sources(sources, site, results[site.site_id])
        return rnd

    work = known + new
    first = {}
    if work:
        with ThreadPoolExecutor(max_workers=len(work)) as pool:
            first = dict(zip([s.site_id for s in work], pool.map(round_one, work)))

    pending = []
    for site in work:
        rnd = first[site.site_id]
        verdict = rnd.decisive.verdict
        if verdict == VERDICT_UNCLEAR:
            decide(site, OUTCOME_UNCONFIRMED, _reasons(rnd.confirmations), [rnd])
        elif verdict == VERDICT_UP:
            decide(site, OUTCOME_RUNNER_BLOCKED,
                   f"{rnd.decisive.reason}, but the monitor could not load it, so the monitor itself is probably blocked", [rnd])
        elif already_down(site):
            decide(site, OUTCOME_CONFIRMED_DOWN, f"still down. {rnd.decisive.reason}", [rnd])   # no waiting for an old outage
        else:
            pending.append(site)

    if pending:
        sleep(settings.confirm_wait_seconds)    # one shared wait, so a short blip has time to clear
        try:
            again = recheck(pending) or {}
        except Exception as exc:
            log.warning("The second runner check failed (%s).", type(exc).__name__)
            again = {}

        def round_two(site):
            previous, newer = results[site.site_id], again.get(site.site_id)
            rnd = ConfirmRound(2)
            if newer is None:
                rnd.runner_note = "could not be repeated"
                return rnd, None
            rnd.runner_note = f"{'still failing' if newer.verdict == classify.VERDICT_DOWN else 'now answers'}: {_describe(newer)}"
            if newer.verdict != classify.VERDICT_DOWN or newer.signal == classify.DNS_FAIL:
                return rnd, merge_runner_result(previous, newer)
            rnd.confirmations = ask_sources(sources, site, newer)
            return rnd, merge_runner_result(previous, newer)

        with ThreadPoolExecutor(max_workers=len(pending)) as pool:
            second = list(pool.map(round_two, pending))
        minutes = max(1, round(settings.confirm_wait_seconds / 60))
        for site, (rnd, merged) in zip(pending, second):
            rounds = [first[site.site_id], rnd]
            if merged is None:
                decide(site, OUTCOME_UNCONFIRMED, "the second check by the monitor could not be run", rounds)
                continue
            run.replaced[site.site_id] = merged
            if merged.verdict != classify.VERDICT_DOWN:
                decide(site, OUTCOME_BLIP, "it failed in the first check and the monitor could load it a few minutes later", rounds)
            elif merged.signal == classify.DNS_FAIL:
                decide(site, OUTCOME_CONFIRMED_DOWN, "the domain no longer resolves (two public resolvers agree)", rounds)
            elif rnd.decisive.verdict == VERDICT_DOWN:
                decide(site, OUTCOME_CONFIRMED_DOWN,
                       f"the monitor and most outside locations could not load it, in two checks about {minutes} minute{'' if minutes == 1 else 's'} apart", rounds)
            elif rnd.decisive.verdict == VERDICT_UP:
                decide(site, OUTCOME_BLIP,
                       "most outside locations could load it in the second check, so the outage looks over", rounds)
            else:
                decide(site, OUTCOME_UNCONFIRMED, _reasons(rnd.confirmations), rounds)
    return run


def _safe_ip(lookup) -> str:
    try:
        return lookup() or ""
    except Exception:
        return ""


# ----------------------------------------------------------------------------------------------
# Evidence for alerts
# ----------------------------------------------------------------------------------------------
def evidence_rows(outcome) -> list:
    """The proof that goes into every alert that came out of a confirmation: [(label, value), ...]."""
    if outcome is None:
        return []
    rows = [("Checked from IP", outcome.runner_ip or "unknown (the address lookup failed)")]
    for rnd in outcome.rounds:
        if rnd.runner_note:
            rows.append((f"Round {rnd.number}, the monitor", rnd.runner_note))
        for confirmation in rnd.confirmations:
            when = f"{fmt_utc(confirmation.started_at)} / {fmt_time(confirmation.started_at)}" if confirmation.started_at else "no time"
            rows.append((f"Round {rnd.number}, {confirmation.source}", f"{confirmation.reason} ({when})"))
            for probe in confirmation.probes:
                kind = f", {probe.kind}" if probe.kind else ""
                rows.append((f"  Round {rnd.number}: {probe.location}", f"{probe.network}{kind}: {probe.detail}"))
            if confirmation.measurement_url:
                rows.append((f"Round {rnd.number}, measurement", f"{confirmation.measurement_id}  {confirmation.measurement_url}"))
    return rows
