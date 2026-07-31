"""Notification channel implementations (spec §21, §27, §28.3).

All channels are **push-only** (outbound HTTPS or SMTP), so a host running Ares
never has to expose an inbound port to be alertable. Secrets are supplied via
env vars in preference to config. Each channel fails soft: a delivery error is
logged and flips the channel's health flag but never breaks the investigation
cycle (spec §25.2 notification outage).
"""

from __future__ import annotations

import json
import logging
import smtplib
import urllib.request
from email.mime.text import MIMEText

from ares.notifications.base import Notification, Notifier

log = logging.getLogger("ares.notifications")

# Severity → display colour / label used by rich channels.
_SLACK_COLOR = {
    "critical": "#B00020",
    "high": "#D93025",
    "medium": "#F9AB00",
    "low": "#1A73E8",
    "info": "#5F6368",
}
_EMOJI = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪"}

# PagerDuty Events API v2 severities are a fixed set.
_PD_SEVERITY = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}


def _post_json(url: str, payload: dict, headers: dict | None = None, timeout: int = 10) -> int:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(  # noqa: S310 - operator-configured URL
        url, data=data, headers={"Content-Type": "application/json", **(headers or {})}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.status


class SlackNotifier(Notifier):
    """Slack incoming webhook (spec §27). The recommended default for teams."""

    name = "slack"

    def __init__(self, webhook_url: str) -> None:
        self._url = webhook_url

    def send(self, message: Notification) -> None:
        emoji = _EMOJI.get(message.severity, "")
        header = f"{emoji} *{message.severity.upper()}* — {message.title}"
        fields = message.body or ""
        if message.case_id:
            fields += f"\n`case {message.case_id}`"
        payload = {
            "text": f"{header}\n{fields}",
            "attachments": [
                {
                    "color": _SLACK_COLOR.get(message.severity, "#5F6368"),
                    "blocks": [
                        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
                        {"type": "section", "text": {"type": "mrkdwn", "text": fields or "—"}},
                    ],
                }
            ],
        }
        _post_json(self._url, payload)


class WebhookNotifier(Notifier):
    """Generic JSON webhook — route incidents into any internal system."""

    name = "webhook"

    def __init__(self, url: str) -> None:
        self._url = url

    def send(self, message: Notification) -> None:
        _post_json(
            self._url,
            {
                "source": "ares",
                "title": message.title,
                "body": message.body,
                "severity": message.severity,
                "case_id": message.case_id,
                "url": message.url,
            },
        )


class PagerDutyNotifier(Notifier):
    """PagerDuty Events API v2 — page on-call for the most urgent incidents.

    Uses ``dedup_key = case_id`` so repeated notifications for one case update a
    single PagerDuty incident instead of paging repeatedly (spec §18.2 dedup).
    """

    name = "pagerduty"
    ENQUEUE_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str) -> None:
        self._routing_key = routing_key

    def send(self, message: Notification) -> None:
        payload = {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "dedup_key": message.case_id or message.title,
            "payload": {
                "summary": f"{message.title}: {message.body}"[:1024],
                "severity": _PD_SEVERITY.get(message.severity, "warning"),
                "source": "ares",
                "custom_details": {"case_id": message.case_id, "body": message.body},
            },
        }
        _post_json(self.ENQUEUE_URL, payload)


class EmailNotifier(Notifier):
    """SMTP email — the universal fallback when no chat/paging tool is in use."""

    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        from_addr: str,
        to_addrs: list[str],
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = True,
    ) -> None:
        self._host = host
        self._port = port
        self._from = from_addr
        self._to = to_addrs
        self._user = username
        self._password = password
        self._use_tls = use_tls

    def send(self, message: Notification) -> None:
        body = f"Severity: {message.severity}\n"
        if message.case_id:
            body += f"Case: {message.case_id}\n"
        body += f"\n{message.body}\n"
        msg = MIMEText(body)
        msg["Subject"] = f"[Ares][{message.severity.upper()}] {message.title}"
        msg["From"] = self._from
        msg["To"] = ", ".join(self._to)
        with smtplib.SMTP(self._host, self._port, timeout=15) as smtp:
            if self._use_tls:
                smtp.starttls()
            if self._user and self._password:
                smtp.login(self._user, self._password)
            smtp.sendmail(self._from, self._to, msg.as_string())
