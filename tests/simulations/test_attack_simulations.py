"""Safe attack simulations using controlled fixtures (spec 35.3).

These build event sequences that mimic attacker behaviour without running any
dangerous payloads, and assert the pipeline classifies them correctly.
"""

from ares import Ares
from ares.events import EventType
from tests.fixtures.factory import (
    connect_event,
    exec_event,
    file_event,
    login_event,
)


def _run(config, events):
    client = Ares(config)
    client.store.write_events(events)
    client.investigate_now()
    cases = client.cases.list()
    client.close()
    return cases


def test_reverse_shell_chain_flagged(config):
    events = [
        exec_event("/bin/sh", name="sh", parent_name="nginx", parent_is_network_service=True),
        file_event(EventType.FILE_CREATE, "/tmp/.cache-x", executable=True),
        exec_event("/tmp/.cache-x"),
        connect_event("203.0.113.20:443"),
        file_event(EventType.FILE_DELETE, "/tmp/.cache-x"),
    ]
    cases = _run(config, events)
    assert cases
    top = max(cases, key=lambda c: c["risk_score"])
    assert top["risk_score"] >= 0.6
    assert top["priority"] in {"medium", "high", "critical"}


def test_persistence_via_cron(config):
    events = [
        exec_event("/bin/bash", name="bash"),
        file_event(EventType.FILE_CREATE, "/etc/cron.d/backdoor"),
    ]
    cases = _run(config, events)
    # Cron persistence should surface at least a retained/reviewable case.
    assert any("cron" in (c.get("summary") or "").lower() or c["risk_score"] > 0 for c in cases)


def test_unauthorized_ssh_key(config):
    events = [file_event(EventType.FILE_MODIFY, "/home/deploy/.ssh/authorized_keys")]
    cases = _run(config, events)
    assert cases


def test_brute_force_then_success(config):
    events = [
        login_event(EventType.IDENTITY_LOGIN_FAILED, "root", "198.51.100.7") for _ in range(6)
    ]
    events.append(login_event(EventType.IDENTITY_LOGIN, "root", "198.51.100.7"))
    cases = _run(config, events)
    assert cases


def test_benign_activity_low_priority(config):
    # Normal web server serving traffic to an internal backend, repeated.
    events = []
    for _ in range(3):
        events.append(connect_event("10.0.0.5:5432", external=False))
        events.append(exec_event("/usr/bin/backup-agent", name="backup-agent", uid=1000))
    client = Ares(config)
    client.store.write_events(events)
    client.investigate_now()
    cases = client.cases.list()
    client.close()
    # No high/critical cases from benign internal activity.
    assert all(c["priority"] not in {"high", "critical"} for c in cases)
