"""Investigator + verdict tests (spec 19, 35.1)."""

from ares.cases import CaseBuilder
from ares.correlation import Correlator
from ares.detection import DetectionEngine
from ares.events import EventType
from ares.investigator import Investigator
from ares.investigator.tools import InvestigatorTools
from tests.fixtures.factory import connect_event, exec_event, file_event


def _malicious_case(store, config):
    eng = DetectionEngine(store, host_role="test")
    shell = exec_event("/bin/sh", name="sh", parent_name="nginx", parent_is_network_service=True)
    created = file_event(EventType.FILE_CREATE, "/tmp/.cache-x", executable=True)
    executed = exec_event("/tmp/.cache-x")
    connected = connect_event("203.0.113.20:443")
    deleted = file_event(EventType.FILE_DELETE, "/tmp/.cache-x")
    events = [shell, created, executed, connected, deleted]
    store.write_events(events)
    findings = []
    for e in events:
        findings.extend(eng.evaluate(e))
    seqs = Correlator(store, host_role="test").correlate(events, findings)
    builder = CaseBuilder(store, config)
    case, _ = builder.build(seqs[0], findings)
    return store.get_case(case["case_id"])


def test_local_investigator_produces_verdict(store, config):
    case = _malicious_case(store, config)
    verdict = Investigator(store, config).investigate_case(case)
    assert verdict.classification in {"suspicious", "likely_malicious", "malicious"}
    assert verdict.evidence
    assert verdict.recommended_actions
    # Verdict persisted.
    saved = store.verdicts_for_case(case["case_id"])
    assert saved and saved[0]["classification"] == verdict.classification


def test_investigation_audit_log_recorded(store, config):
    case = _malicious_case(store, config)
    Investigator(store, config).investigate_case(case)
    import json

    with store._lock:
        row = store._conn.execute("SELECT audit_log, tool_calls FROM investigations").fetchone()
    assert row is not None
    json.loads(row["audit_log"])  # valid JSON list


def test_tools_are_read_only_and_typed(store):
    tools = InvestigatorTools(store=store, host_id="h")
    # Unknown tool rejected.
    assert tools.dispatch("rm_rf", {"path": "/"}).ok is False
    # Reputation tool returns structured data and increments the audit log.
    res = tools.dispatch("check_destination_reputation", {"destination": "1.2.3.4:443"})
    assert res.ok
    assert tools.call_count == 2
    assert len(tools.audit_log) == 2


def test_case_dedup(store, config):
    """Repeated identical activity updates one case, not many (spec 18.2)."""
    _malicious_case(store, config)
    n_after_first = len(store.list_cases())
    _malicious_case(store, config)
    n_after_second = len(store.list_cases())
    assert n_after_second == n_after_first
