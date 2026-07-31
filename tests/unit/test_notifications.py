"""Notification routing tests (spec §27)."""

from ares.config import Config
from ares.notifications import NotificationManager
from ares.notifications.base import Notification, Notifier
from ares.notifications.severity import meets_threshold


class _Capture(Notifier):
    name = "capture"

    def __init__(self):
        self.sent = []

    def send(self, message):
        self.sent.append(message)


def _mgr(monkeypatch, **notif):
    # No env vars leaking in from the host.
    for k in list(__import__("os").environ):
        if k.startswith("ARES_"):
            monkeypatch.delenv(k, raising=False)
    cfg = Config.model_validate({"notifications": {"console": False, **notif}})
    return NotificationManager(cfg)


def test_severity_helper():
    assert meets_threshold("critical", "high")
    assert meets_threshold("high", "high")
    assert not meets_threshold("medium", "high")


def test_global_min_severity_drops_low(monkeypatch):
    mgr = _mgr(monkeypatch, min_severity="high")
    cap = _Capture()
    mgr.register(cap, min_severity="info")
    mgr.notify(Notification(title="x", body="", severity="medium"))
    assert cap.sent == []  # dropped by global floor before channels
    mgr.notify(Notification(title="y", body="", severity="critical"))
    assert len(cap.sent) == 1


def test_per_channel_threshold(monkeypatch):
    mgr = _mgr(monkeypatch, min_severity="low")
    high_only = _Capture()
    mgr.register(high_only, min_severity="critical")
    mgr.notify(Notification(title="h", body="", severity="high"))
    assert high_only.sent == []  # channel wants critical
    mgr.notify(Notification(title="c", body="", severity="critical"))
    assert len(high_only.sent) == 1


def test_slack_channel_from_env(monkeypatch):
    monkeypatch.setenv("ARES_SLACK_WEBHOOK", "https://hooks.slack.example/x")
    cfg = Config.model_validate({"notifications": {"console": False}})
    mgr = NotificationManager(cfg)
    assert "slack" in mgr.channels


def test_pagerduty_from_env_paging_only_critical(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("ARES_"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ARES_PAGERDUTY_ROUTING_KEY", "R0UT1NGKEY")
    cfg = Config.model_validate({"notifications": {"console": False}})
    mgr = NotificationManager(cfg)
    assert "pagerduty" in mgr.channels


def test_notifier_failure_is_isolated(monkeypatch):
    mgr = _mgr(monkeypatch, min_severity="info")

    class Boom(Notifier):
        name = "boom"

        def send(self, message):
            raise RuntimeError("down")

    ok = _Capture()
    mgr.register(Boom(), min_severity="info")
    mgr.register(ok, min_severity="info")
    mgr.notify(Notification(title="t", body="", severity="high"))
    # The working channel still received it; manager marks itself unhealthy.
    assert len(ok.sent) == 1
    assert mgr.healthy is False
