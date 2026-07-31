"""Correlation and baseline tests (spec 16, 17, 35.1)."""

from ares.baseline import BaselineEngine
from ares.correlation import Correlator
from ares.detection import DetectionEngine
from ares.events import EventType
from tests.fixtures.factory import connect_event, exec_event, file_event


def test_sequence_scoring_full_chain(store):
    eng = DetectionEngine(store, host_role="test")
    nginx = exec_event("/usr/sbin/nginx", name="nginx", pid=100)
    store.upsert_process(
        {"process_id": nginx.process_id, "host_id": "host_test", "pid": 100, "executable": "nginx"}
    )
    shell = exec_event(
        "/bin/sh",
        name="sh",
        pid=101,
        parent_id=nginx.process_id,
        parent_name="nginx",
        parent_is_network_service=True,
    )
    store.upsert_process(
        {
            "process_id": shell.process_id,
            "host_id": "host_test",
            "pid": 101,
            "parent_id": nginx.process_id,
            "executable": "/bin/sh",
        }
    )
    created = file_event(EventType.FILE_CREATE, "/tmp/.cache-x", executable=True)
    executed = exec_event("/tmp/.cache-x", pid=102, parent_id=shell.process_id)
    connected = connect_event("203.0.113.20:443")
    deleted = file_event(EventType.FILE_DELETE, "/tmp/.cache-x")

    events = [nginx, shell, created, executed, connected, deleted]
    findings = []
    for e in events:
        findings.extend(eng.evaluate(e))

    seqs = Correlator(store, host_role="test").correlate(events, findings)
    top = seqs[0]
    assert top.score >= 0.6
    assert any("chain" in r.lower() for r in top.reasons)
    # Rendered sequence should be human-readable.
    assert top.render()


def test_baseline_novelty_decreases_with_observations(store):
    be = BaselineEngine(store)
    ev = exec_event("/usr/bin/backup-agent", name="backup-agent")
    first = be.deviation(ev)
    assert first > 0.9  # never seen
    for _ in range(10):
        be.observe(ev)
    later = be.deviation(ev)
    assert later < first


def test_baseline_excludes_high_risk(store):
    be = BaselineEngine(store)
    ev = exec_event("/tmp/.evil")
    be.observe(ev, high_risk=True)
    # High-risk event must not be learned (poisoning protection, spec 17.4).
    assert be.deviation(ev) > 0.9


def test_baseline_freeze_blocks_updates(store):
    be = BaselineEngine(store)
    be.freeze(True)
    ev = exec_event("/usr/bin/curl")
    be.observe(ev)
    assert be.deviation(ev) > 0.9
