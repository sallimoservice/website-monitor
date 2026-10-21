"""Email notifier using plain SMTP (Titan, Gmail or any other provider).

Port 465 uses SSL straight away. Any other port (587, 2525...) uses STARTTLS.
"""

from __future__ import annotations

import html
import logging
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr

from .. import dryrun
from ..alerts import EMOJI, Alert, group_summary, top_kind
from ..timeutil import fmt_time

log = logging.getLogger("monitor.email")

SEND_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 5
SMTP_TIMEOUT_SECONDS = 30

_COLORS = {
    "DOWN": "#d93025",
    "RECOVERED": "#188038",
    "SECURITY": "#b3261e",
    "WARNING": "#e37400",
    "CRASH": "#b3261e",
    "INFO": "#1a73e8",
    "TEST": "#5f6368",
}


def build_subject(alerts) -> str:
    """One alert gives '🔴 DOWN: ClientSite - example.com'. Several are grouped."""
    if len(alerts) == 1:
        alert = alerts[0]
        subject = f"{alert.emoji} {alert.label}: {alert.site_name}"
        return f"{subject} - {alert.host}" if alert.host else subject
    return f"{EMOJI[top_kind(alerts)]} Website Monitor - {group_summary(alerts)}"


def build_text(alerts) -> str:
    blocks = []
    for alert in alerts:
        lines = [f"{alert.emoji} {alert.label} - {alert.site_name}"]
        if alert.url:
            lines.append(f"URL: {alert.url}")
        lines.append(f"What happened: {alert.summary}")
        lines.extend(f"{label}: {value}" for label, value in alert.details)
        lines.append(f"Time: {fmt_time(alert.ts)}")
        blocks.append("\n".join(lines))
    return ("\n\n" + "-" * 40 + "\n\n").join(blocks) + "\n\n-- \nSent by Website Monitor"


def build_html(alerts) -> str:
    cards = []
    for alert in alerts:
        color = _COLORS.get(alert.kind, "#5f6368")
        rows = [("What happened", alert.summary)]
        rows.extend(alert.details)
        rows.append(("Time", fmt_time(alert.ts)))
        row_html = "".join(
            f'<tr><td style="padding:3px 12px 3px 0;color:#5f6368;white-space:nowrap">{html.escape(str(k))}</td>'
            f'<td style="padding:3px 0">{html.escape(str(v))}</td></tr>'
            for k, v in rows
        )
        url_html = ""
        if alert.url:
            safe_url = html.escape(alert.url, quote=True)
            url_html = f'<div style="margin:2px 0 8px"><a href="{safe_url}" style="color:#1a73e8">{html.escape(alert.url)}</a></div>'
        cards.append(
            f'<div style="border-left:5px solid {color};background:#f8f9fa;padding:12px 16px;margin:0 0 14px">'
            f'<div style="font-size:17px;font-weight:bold;color:{color}">{alert.emoji} {html.escape(alert.label)} - {html.escape(alert.site_name)}</div>'
            f"{url_html}<table style=\"font-size:14px;border-collapse:collapse\">{row_html}</table></div>"
        )
    return (
        '<html><body style="font-family:Arial,Helvetica,sans-serif;color:#202124;max-width:620px">'
        + "".join(cards)
        + '<div style="font-size:12px;color:#80868b">Sent by Website Monitor</div></body></html>'
    )


def build_message(settings, alerts) -> EmailMessage:
    """Build the email with the headers that help it reach the inbox."""
    from_address = parseaddr(settings.smtp_from)[1] or settings.smtp_user
    domain = from_address.split("@")[-1] if "@" in from_address else None

    msg = EmailMessage()
    msg["Subject"] = build_subject(alerts)
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = ", ".join(settings.email_to)
    msg["Reply-To"] = from_address
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=domain)
    msg["Auto-Submitted"] = "auto-generated"
    if any(alert.high_priority for alert in alerts):
        msg["X-Priority"] = "1 (Highest)"
        msg["Importance"] = "High"
        msg["X-MSMail-Priority"] = "High"
    # Quoted-printable keeps the emoji safe on any mail server (plain 8-bit text can raise spam scores).
    msg.set_content(build_text(alerts), cte="quoted-printable")
    msg.add_alternative(build_html(alerts), subtype="html")
    return msg


class EmailNotifier:
    name = "email"

    def __init__(self, settings, sleep=time.sleep):
        self.settings = settings
        self._sleep = sleep

    def accepts(self, alert: Alert) -> bool:
        return True  # email gets every alert type

    def send(self, alerts) -> bool:
        """Send all alerts as ONE email. Returns True if the server accepted it."""
        dryrun.forbid("send an email")
        s = self.settings
        msg = build_message(s, alerts)
        envelope_from = parseaddr(s.smtp_from)[1] or s.smtp_user

        for attempt in range(1, SEND_ATTEMPTS + 1):
            try:
                refused = self._send_once(msg, envelope_from)
                if refused:
                    log.warning("Email: %d recipient(s) were refused by the server.", len(refused))
                log.info("Email sent (%d alert(s)).", len(alerts))
                return True
            except smtplib.SMTPAuthenticationError as exc:
                # Retrying a wrong password can lock the account, so stop here.
                log.error(
                    "Email login failed (%s). Check SMTP_USER and SMTP_PASSWORD, and the port.",
                    self._safe(exc),
                )
                return False
            except (smtplib.SMTPException, OSError) as exc:
                log.error(
                    "Email attempt %d of %d failed (%s: %s).%s",
                    attempt,
                    SEND_ATTEMPTS,
                    type(exc).__name__,
                    self._safe(exc),
                    " Check SMTP_HOST, SMTP_PORT and that the port is not blocked." if isinstance(exc, OSError) else "",
                )
                if attempt < SEND_ATTEMPTS:
                    self._sleep(RETRY_DELAY_SECONDS)
        return False

    def _send_once(self, msg, envelope_from) -> dict:
        s = self.settings
        context = ssl.create_default_context()
        if s.smtp_port == 465:
            server = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=SMTP_TIMEOUT_SECONDS, context=context)
        else:
            server = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=SMTP_TIMEOUT_SECONDS)
        with server:
            if s.smtp_port != 465:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
            server.login(s.smtp_user, s.smtp_password)
            return server.send_message(msg, from_addr=envelope_from, to_addrs=list(s.email_to))

    def _safe(self, exc) -> str:
        """Error text with the password removed, so it can never reach the log."""
        text = str(exc)
        password = self.settings.smtp_password
        return text.replace(password, "***") if password else text
