"""Reads configuration from environment variables (and an optional local .env file).

In GitHub Actions every value comes from a repository secret, so nothing
sensitive is ever stored in the (public) repository.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger("monitor.config")

# A normal desktop Chrome. Override with the USER_AGENT setting when browsers move on.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
UPTIME_SOURCES = ("self", "external")


# Settings that no longer do anything. If one is still set, say so once instead of ignoring it silently.
REMOVED_SETTINGS = {
    "REQUEST_TIMEOUT_SECONDS": (
        "is ignored. It is replaced by CONNECT_TIMEOUT_SECONDS (default 10) and READ_TIMEOUT_SECONDS (default 30), "
        "and by \"read_timeout_seconds\" on a single site."
    ),
    "CLOUDFLARE_RETRY_GAP_SECONDS": (
        "is ignored. Every failing site now gets 3 visits at least RETRY_GAP_SECONDS (default 60) apart."
    ),
}
MIN_RECOMMENDED_RETRY_GAP = 60.0


class ConfigError(Exception):
    """A problem the user can fix by editing their settings."""


def load_dotenv(path: str = ".env") -> None:
    """Load KEY=value lines from a local .env file (for testing on your own PC).

    Real environment variables always win, so GitHub secrets are never overridden.
    """
    env_file = Path(path)
    if not env_file.is_file():
        return
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _env(name: str, default: str = "") -> str:
    """Read a setting. A missing or empty (unset GitHub secret) value gives the default."""
    value = os.environ.get(name, "").strip()
    return value or default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _env_number(name: str, default, cast):
    raw = _env(name)
    if not raw:
        return default
    try:
        return cast(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number.") from None


def _split_list(raw: str) -> tuple:
    parts = raw.replace(";", ",").split(",")
    return tuple(p.strip() for p in parts if p.strip())


@dataclass(frozen=True)
class Settings:
    # Email (SMTP)
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    email_to: tuple
    # Behaviour
    state_salt: str
    state_path: str
    healthcheck_url: str
    connect_timeout: float
    read_timeout: float
    retry_attempts: int
    retry_gap_seconds: float
    text_recheck_gap_seconds: float
    stagger_seconds: float
    default_slow_seconds: float
    check_every_hours: float
    user_agent: str
    notify_on_blocked_change: bool
    dry_run: bool
    down_reminder_hours: float
    max_workers: int
    # Environment
    in_actions: bool
    real_names_in_logs: bool

    @property
    def email_enabled(self) -> bool:
        return bool(self.smtp_user and self.smtp_password and self.email_to)

    def log_name(self, site: "Site") -> str:
        """Name to use in logs. Public logs get 'Site 03' instead of the client name."""
        return site.name if self.real_names_in_logs else site.label

    def sensitive_values(self) -> list:
        """Secrets that must never be printed."""
        return [self.smtp_password, self.smtp_user, self.smtp_from, self.healthcheck_url, *self.email_to]


@dataclass(frozen=True)
class Site:
    index: int
    name: str
    url: str
    site_id: str
    expected_domain: str
    keywords_to_watch: tuple = ()
    slow_threshold_seconds: float = 8.0
    read_timeout_seconds: Optional[float] = None   # per-site override of how long to wait for an answer
    behind_cloudflare: bool = False     # the site is proxied by Cloudflare
    uptime_source: str = "self"         # "external" = another monitor owns uptime alerts
    expected_text: str = ""             # must appear on a normal 200 page (empty = not checked)
    # Off by default. When true, "connection refused" on this site is a warning, not DOWN.
    connection_refused_is_warning: bool = False

    @property
    def label(self) -> str:
        return f"Site {self.index:02d}"

    @property
    def host(self) -> str:
        return (urlparse(self.url).hostname or "").lower()


def load_settings() -> Settings:
    in_actions = _env("GITHUB_ACTIONS").lower() == "true"
    # Real names in logs only when testing on your own PC, never in public Actions logs.
    real_names = (not in_actions) and _env("LOG_REAL_NAMES", "true").lower() != "false"
    smtp_user = _env("SMTP_USER")
    return Settings(
        smtp_host=_env("SMTP_HOST", "smtp.titan.email"),
        smtp_port=_env_number("SMTP_PORT", 465, int),
        smtp_user=smtp_user,
        smtp_password=_env("SMTP_PASSWORD"),
        smtp_from=_env("SMTP_FROM", smtp_user),
        email_to=_split_list(_env("EMAIL_TO")),
        state_salt=_env("STATE_SALT"),
        state_path=_env("STATE_PATH", "state.json"),
        healthcheck_url=_env("HEALTHCHECK_URL"),
        connect_timeout=_env_number("CONNECT_TIMEOUT_SECONDS", 10.0, float),
        read_timeout=_env_number("READ_TIMEOUT_SECONDS", 30.0, float),
        retry_attempts=3,
        # Minimum time between the START of one attempt and the start of the next.
        retry_gap_seconds=_env_number("RETRY_GAP_SECONDS", 60.0, float),
        text_recheck_gap_seconds=_env_number("TEXT_RECHECK_GAP_SECONDS", 30.0, float),
        # First visits start at random moments within this many seconds, so 17 requests never
        # hit shared hosting in the same second. 0 switches it off.
        stagger_seconds=_env_number("STAGGER_SECONDS", 20.0, float),
        default_slow_seconds=_env_number("DEFAULT_SLOW_SECONDS", 8.0, float),
        check_every_hours=_env_number("CHECK_EVERY_HOURS", 8.0, float),
        user_agent=_env("USER_AGENT", DEFAULT_USER_AGENT),
        notify_on_blocked_change=_env_bool("NOTIFY_ON_BLOCKED_CHANGE", False),
        dry_run=_env_bool("DRY_RUN", False),
        down_reminder_hours=8.0,
        max_workers=20,
        in_actions=in_actions,
        real_names_in_logs=real_names,
    )


def warn_about_removed_settings() -> None:
    """One masked line per removed setting that is still set (the value is never printed)."""
    for name, hint in REMOVED_SETTINGS.items():
        if _env(name):
            log.warning("Setting %s is still set but %s", name, hint)
    gap = _env("RETRY_GAP_SECONDS")
    try:
        if gap and float(gap) < MIN_RECOMMENDED_RETRY_GAP:
            log.warning(
                "RETRY_GAP_SECONDS is set below %g. The rules call for visits at least %g seconds apart.",
                MIN_RECOMMENDED_RETRY_GAP,
                MIN_RECOMMENDED_RETRY_GAP,
            )
    except ValueError:
        pass  # a non-number is reported when the settings are loaded


def make_site_id(salt: str, url: str) -> str:
    """Anonymous ID for a site. Only this hash is stored in state.json, never the URL."""
    key = (salt or "website-monitor").encode("utf-8")
    normalized = url.strip().lower().rstrip("/")
    return hmac.new(key, normalized.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if "//" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0]
    return value[4:] if value.startswith("www.") else value


def _read_sites_json() -> str:
    raw = _env("SITES_JSON")
    if raw:
        return raw
    sites_file = _env("SITES_FILE")
    if sites_file:
        path = Path(sites_file)
        if not path.is_file():
            raise ConfigError("SITES_FILE points to a file that does not exist.")
        return path.read_text(encoding="utf-8")
    raise ConfigError(
        "No websites configured. Add the SITES_JSON secret (or set SITES_FILE in your .env). "
        "See sites.example.json for the format."
    )


@dataclass
class SiteLoad:
    sites: list = field(default_factory=list)
    skipped: int = 0                                  # entries ignored because they were malformed
    skipped_ids: list = field(default_factory=list)   # their state IDs, so saved state is kept


class _EntryError(Exception):
    """One website entry is unusable. The other entries are not affected."""


def _parse_entry(settings: Settings, position: int, entry, seen_ids: set) -> Site:
    where = f"Website number {position} in SITES_JSON"
    if not isinstance(entry, dict):
        raise _EntryError(f"{where} must be an object like {{\"name\": ..., \"url\": ...}}.")
    name = str(entry.get("name", "")).strip()
    url = str(entry.get("url", "")).strip()
    if not name:
        raise _EntryError(f"{where} is missing \"name\".")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise _EntryError(f"{where} needs a \"url\" starting with http:// or https://.")
    site_id = make_site_id(settings.state_salt, url)
    if site_id in seen_ids:
        raise _EntryError(f"{where} repeats a URL that is already in the list.")

    keywords = entry.get("keywords_to_watch", [])
    if not isinstance(keywords, list):
        raise _EntryError(f"{where}: \"keywords_to_watch\" must be a list of words.")
    try:
        slow = float(entry.get("slow_threshold_seconds", settings.default_slow_seconds))
    except (TypeError, ValueError):
        raise _EntryError(f"{where}: \"slow_threshold_seconds\" must be a number.") from None
    if slow <= 0:
        raise _EntryError(f"{where}: \"slow_threshold_seconds\" must be above 0.")
    for flag in ("connection_refused_is_warning", "behind_cloudflare"):
        if not isinstance(entry.get(flag, False), bool):
            # A quoted "false" would count as true, so only real true/false is accepted.
            raise _EntryError(f"{where}: \"{flag}\" must be true or false (no quotes).")
    read_timeout = entry.get("read_timeout_seconds")
    if read_timeout is not None:
        if isinstance(read_timeout, bool) or not isinstance(read_timeout, (int, float)) or not 0 < read_timeout <= 300:
            raise _EntryError(f"{where}: \"read_timeout_seconds\" must be a number above 0 and at most 300.")
    uptime_source = entry.get("uptime_source", "self")
    if uptime_source not in UPTIME_SOURCES:
        raise _EntryError(f"{where}: \"uptime_source\" must be \"self\" or \"external\".")
    expected_text = entry.get("expected_text", "")
    if not isinstance(expected_text, str):
        raise _EntryError(f"{where}: \"expected_text\" must be text.")

    seen_ids.add(site_id)
    return Site(
        index=position,
        name=name,
        url=url,
        site_id=site_id,
        expected_domain=_normalize_domain(str(entry.get("expected_domain") or parsed.hostname)),
        keywords_to_watch=tuple(str(k).strip() for k in keywords if str(k).strip()),
        slow_threshold_seconds=slow,
        read_timeout_seconds=float(read_timeout) if read_timeout is not None else None,
        behind_cloudflare=entry.get("behind_cloudflare", False),
        uptime_source=uptime_source,
        expected_text=expected_text.strip(),
        connection_refused_is_warning=entry.get("connection_refused_is_warning", False),
    )


def load_sites_report(settings: Settings) -> SiteLoad:
    """Parse the website list. A broken entry is skipped (and counted), never fatal.

    Only a list that cannot be read at all stops the run. Messages never echo your data.
    """
    try:
        data = json.loads(_read_sites_json())
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"SITES_JSON is not valid JSON (problem near line {exc.lineno}, column {exc.colno}). "
            "Check commas, quotes and brackets."
        ) from None
    if not isinstance(data, list) or not data:
        raise ConfigError("SITES_JSON must be a JSON list with at least one website.")

    report, seen_ids = SiteLoad(), set()
    legacy = sum(1 for entry in data if isinstance(entry, dict) and "allow_auth" in entry)
    if legacy:
        log.warning(
            "\"allow_auth\" is ignored (found in %d website entr%s). 401, 403, 405 and 429 answers never "
            "cause DOWN any more, so it is no longer needed.",
            legacy,
            "y" if legacy == 1 else "ies",
        )
    for position, entry in enumerate(data, start=1):
        try:
            report.sites.append(_parse_entry(settings, position, entry, seen_ids))
        except _EntryError as exc:
            report.skipped += 1
            log.warning("Entry skipped. %s", exc)
            if isinstance(entry, dict) and isinstance(entry.get("url"), str) and entry["url"].strip():
                report.skipped_ids.append(make_site_id(settings.state_salt, entry["url"]))
    if not report.sites:
        raise ConfigError("None of the websites in SITES_JSON could be used. See the warnings above.")
    return report


def load_sites(settings: Settings) -> list:
    """The usable websites only (see load_sites_report for the skipped count)."""
    return load_sites_report(settings).sites
