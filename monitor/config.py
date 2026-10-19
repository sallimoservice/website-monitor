"""Reads configuration from environment variables (and an optional local .env file).

In GitHub Actions every value comes from a repository secret, so nothing
sensitive is ever stored in the (public) repository.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


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
    request_timeout: float
    retry_attempts: int
    retry_gap_seconds: float
    cloudflare_retry_gap_seconds: float
    default_slow_seconds: float
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
        request_timeout=_env_number("REQUEST_TIMEOUT_SECONDS", 30.0, float),
        retry_attempts=4,
        retry_gap_seconds=_env_number("RETRY_GAP_SECONDS", 15.0, float),
        cloudflare_retry_gap_seconds=_env_number("CLOUDFLARE_RETRY_GAP_SECONDS", 30.0, float),
        default_slow_seconds=_env_number("DEFAULT_SLOW_SECONDS", 8.0, float),
        down_reminder_hours=6.0,
        max_workers=20,
        in_actions=in_actions,
        real_names_in_logs=real_names,
    )


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


def load_sites(settings: Settings) -> list:
    """Parse and validate the list of websites. Error messages never echo your data."""
    try:
        data = json.loads(_read_sites_json())
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"SITES_JSON is not valid JSON (problem near line {exc.lineno}, column {exc.colno}). "
            "Check commas, quotes and brackets."
        ) from None
    if not isinstance(data, list) or not data:
        raise ConfigError("SITES_JSON must be a JSON list with at least one website.")

    sites, seen_urls = [], set()
    for position, entry in enumerate(data, start=1):
        where = f"Website number {position} in SITES_JSON"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be an object like {{\"name\": ..., \"url\": ...}}.")
        name = str(entry.get("name", "")).strip()
        url = str(entry.get("url", "")).strip()
        if not name:
            raise ConfigError(f"{where} is missing \"name\".")
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ConfigError(f"{where} needs a \"url\" starting with http:// or https://.")
        site_id = make_site_id(settings.state_salt, url)
        if site_id in seen_urls:
            raise ConfigError(f"{where} repeats a URL that is already in the list.")
        seen_urls.add(site_id)

        keywords = entry.get("keywords_to_watch", [])
        if not isinstance(keywords, list):
            raise ConfigError(f"{where}: \"keywords_to_watch\" must be a list of words.")
        try:
            slow = float(entry.get("slow_threshold_seconds", settings.default_slow_seconds))
        except (TypeError, ValueError):
            raise ConfigError(f"{where}: \"slow_threshold_seconds\" must be a number.") from None
        if slow <= 0:
            raise ConfigError(f"{where}: \"slow_threshold_seconds\" must be above 0.")
        refused_is_warning = entry.get("connection_refused_is_warning", False)
        if not isinstance(refused_is_warning, bool):
            # A quoted "false" would count as true, so only real true/false is accepted.
            raise ConfigError(f"{where}: \"connection_refused_is_warning\" must be true or false (no quotes).")

        sites.append(
            Site(
                index=position,
                name=name,
                url=url,
                site_id=site_id,
                expected_domain=_normalize_domain(str(entry.get("expected_domain") or parsed.hostname)),
                keywords_to_watch=tuple(str(k).strip() for k in keywords if str(k).strip()),
                slow_threshold_seconds=slow,
                connection_refused_is_warning=refused_is_warning,
            )
        )
    return sites
