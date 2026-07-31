"""Fan notifications out to configured channels with severity routing (spec §27).

Channel secrets are read from env vars in preference to the config file, so a
12-factor / cloud deployment can enable alerting entirely through environment:

    ARES_SLACK_WEBHOOK        Slack incoming webhook URL
    ARES_NOTIFY_WEBHOOK       generic JSON webhook URL
    ARES_PAGERDUTY_ROUTING_KEY  PagerDuty Events API v2 routing key
    ARES_SMTP_HOST / _PORT / _USER / _PASSWORD / _FROM / _TO   email
    ARES_NOTIFY_MIN_SEVERITY  global floor (info|low|medium|high|critical)

A message below the global ``min_severity`` is dropped before any channel is
touched; PagerDuty additionally honours its own (higher) threshold so on-call
is only paged for the most urgent incidents.
"""

from __future__ import annotations

import logging
import os

from rich.console import Console

from ares.config import Config
from ares.notifications.base import Notification, Notifier
from ares.notifications.channels import (
    EmailNotifier,
    PagerDutyNotifier,
    SlackNotifier,
    WebhookNotifier,
)
from ares.notifications.severity import meets_threshold

log = logging.getLogger("ares.notifications")

_CONSOLE_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class ConsoleNotifier(Notifier):
    name = "console"

    def __init__(self) -> None:
        self._console = Console()

    def send(self, message: Notification) -> None:
        style = _CONSOLE_STYLE.get(message.severity, "white")
        self._console.print(f"[{style}] {message.severity.upper()} [/] {message.title}")
        if message.body:
            self._console.print(f"  {message.body}")


def _env(*names: str) -> str | None:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return None


class NotificationManager:
    def __init__(self, config: Config) -> None:
        self._cfg = config.notifications
        self._min_severity = _env("ARES_NOTIFY_MIN_SEVERITY") or self._cfg.min_severity
        self._channels: list[tuple[Notifier, str]] = []  # (notifier, per-channel min_severity)
        self._build_channels()
        self.healthy = True

    # -- channel wiring ----------------------------------------------------

    def _build_channels(self) -> None:
        cfg = self._cfg

        if cfg.console:
            self._add(ConsoleNotifier(), self._min_severity)

        slack = _env("ARES_SLACK_WEBHOOK") or cfg.slack_webhook
        if slack:
            self._add(SlackNotifier(slack), self._min_severity)

        webhook = _env("ARES_NOTIFY_WEBHOOK") or cfg.webhook
        if webhook:
            self._add(WebhookNotifier(webhook), self._min_severity)

        self._build_email(cfg)
        self._build_pagerduty(cfg)

    def _build_email(self, cfg) -> None:
        e = cfg.email
        host = _env("ARES_SMTP_HOST") or e.smtp_host
        to = _env("ARES_SMTP_TO")
        to_addrs = [a.strip() for a in to.split(",")] if to else e.to_addrs
        from_addr = _env("ARES_SMTP_FROM") or e.from_addr
        enabled = e.enabled or bool(_env("ARES_SMTP_HOST"))
        if enabled and host and from_addr and to_addrs:
            self._add(
                EmailNotifier(
                    host=host,
                    port=int(_env("ARES_SMTP_PORT") or e.smtp_port),
                    from_addr=from_addr,
                    to_addrs=to_addrs,
                    username=_env("ARES_SMTP_USER") or e.username,
                    password=_env("ARES_SMTP_PASSWORD") or e.password,
                    use_tls=e.use_tls,
                ),
                self._min_severity,
            )

    def _build_pagerduty(self, cfg) -> None:
        pd = cfg.pagerduty
        key = _env("ARES_PAGERDUTY_ROUTING_KEY") or pd.routing_key
        enabled = pd.enabled or bool(_env("ARES_PAGERDUTY_ROUTING_KEY"))
        if enabled and key:
            # PagerDuty uses its own, higher threshold (default: critical only).
            self._add(PagerDutyNotifier(key), pd.min_severity)

    def _add(self, notifier: Notifier, min_severity: str) -> None:
        self._channels.append((notifier, min_severity))

    def register(self, notifier: Notifier, min_severity: str | None = None) -> None:
        self._add(notifier, min_severity or self._min_severity)

    @property
    def channels(self) -> list[str]:
        return [n.name for n, _ in self._channels]

    # -- delivery ----------------------------------------------------------

    def notify(self, message: Notification) -> None:
        if not meets_threshold(message.severity, self._min_severity):
            return
        for notifier, channel_min in self._channels:
            if not meets_threshold(message.severity, channel_min):
                continue
            try:
                notifier.send(message)
            except Exception:
                self.healthy = False
                log.exception("notifier %s failed", notifier.name)
