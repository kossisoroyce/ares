"""Streaming detection rule tests (spec 12, 35.1)."""

from ares.detection import DetectionEngine
from ares.events import EventType
from tests.fixtures.factory import (
    connect_event,
    exec_event,
    file_event,
    login_event,
)


def _engine(store):
    return DetectionEngine(store, host_role="test")


def test_network_service_spawned_shell(store):
    eng = _engine(store)
    ev = exec_event("/bin/sh", name="sh", parent_name="nginx", parent_is_network_service=True)
    results = eng.evaluate(ev)
    ids = {r.finding.rule_id for r in results}
    assert "PROC_NET_SHELL_001" in ids
    shell_finding = next(r for r in results if r.finding.rule_id == "PROC_NET_SHELL_001")
    assert shell_finding.immediate is True


def test_temp_execution(store):
    eng = _engine(store)
    results = eng.evaluate(exec_event("/tmp/.cache-x"))
    assert "PROC_TEMP_EXEC_002" in {r.finding.rule_id for r in results}


def test_first_seen_destination_only_once(store):
    eng = _engine(store)
    first = eng.evaluate(connect_event("203.0.113.20:443"))
    assert "NET_FIRST_SEEN_005" in {r.finding.rule_id for r in first}
    second = eng.evaluate(connect_event("203.0.113.20:443"))
    assert "NET_FIRST_SEEN_005" not in {r.finding.rule_id for r in second}


def test_authorized_keys(store):
    eng = _engine(store)
    ev = file_event(EventType.FILE_MODIFY, "/root/.ssh/authorized_keys")
    assert "PERSIST_SSH_KEYS_006" in {r.finding.rule_id for r in eng.evaluate(ev)}


def test_sudoers_is_immediate(store):
    eng = _engine(store)
    ev = file_event(EventType.FILE_MODIFY, "/etc/sudoers")
    results = eng.evaluate(ev)
    f = next(r for r in results if r.finding.rule_id == "PRIV_SUDOERS_010")
    assert f.immediate is True
    assert f.finding.severity == "critical"


def test_encoded_arguments(store):
    eng = _engine(store)
    ev = exec_event(
        "/usr/bin/python3",
        argv=["python3", "-c", "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk" + "A" * 40],
    )
    assert "PROC_ENCODED_ARGS_012" in {r.finding.rule_id for r in eng.evaluate(ev)}


def test_failed_login_burst_then_success(store):
    eng = DetectionEngine(store, host_role="test")
    for _ in range(5):
        eng.evaluate(login_event(EventType.IDENTITY_LOGIN_FAILED, "root", "10.0.0.9"))
    results = eng.evaluate(login_event(EventType.IDENTITY_LOGIN, "root", "10.0.0.9"))
    assert "IDENT_BRUTE_FORCE_019" in {r.finding.rule_id for r in results}


def test_suppression_silences_rule(store):
    store.add_suppression("host", {"rule_id": "PROC_TEMP_EXEC_002"}, "known", None)
    eng = _engine(store)
    results = eng.evaluate(exec_event("/tmp/.cache-x"))
    assert "PROC_TEMP_EXEC_002" not in {r.finding.rule_id for r in results}


def test_broken_rule_does_not_crash_engine(store):
    from ares.detection.rule import Rule

    class Boom(Rule):
        rule_id = "BOOM"

        def evaluate(self, event, context):
            raise RuntimeError("boom")

    eng = _engine(store)
    eng.add_rule(Boom())
    # Should still return the temp-exec finding despite Boom raising.
    results = eng.evaluate(exec_event("/tmp/.x"))
    assert "PROC_TEMP_EXEC_002" in {r.finding.rule_id for r in results}
