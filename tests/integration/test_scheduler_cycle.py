"""End-to-end scheduler cycle tests (spec 15, 35.2)."""

from ares.events import EventType
from ares.scheduler import InvestigationScheduler
from tests.fixtures.factory import connect_event, exec_event, file_event


def _seed_attack(store):
    events = [
        exec_event("/bin/sh", name="sh", parent_name="nginx", parent_is_network_service=True),
        file_event(EventType.FILE_CREATE, "/tmp/.cache-x", executable=True),
        exec_event("/tmp/.cache-x"),
        connect_event("203.0.113.20:443"),
        file_event(EventType.FILE_DELETE, "/tmp/.cache-x"),
    ]
    store.write_events(events)
    return events


def test_full_cycle_creates_case_and_verdict(store, config):
    _seed_attack(store)
    sched = InvestigationScheduler(config, store, evidence_dir=config.storage.path + ".ev")
    report = sched.run_cycle()
    assert report.events_processed == 5
    assert report.cases_created >= 1
    assert report.investigations >= 1
    # Events are now marked processed; a second cycle finds nothing new.
    report2 = sched.run_cycle()
    assert report2.events_processed == 0


def test_watermark_advances(store, config):
    events = _seed_attack(store)
    sched = InvestigationScheduler(config, store, evidence_dir=config.storage.path + ".ev")
    sched.run_cycle()
    wm = store.get_state("watermark")
    assert wm["last_event_timestamp_ns"] == max(e.timestamp_ns for e in events)


def test_overlap_lock_skips_second_worker(store, config):
    _seed_attack(store)
    sched = InvestigationScheduler(config, store, evidence_dir=config.storage.path + ".ev")
    # Hold the lock as another owner; the cycle must skip rather than duplicate.
    assert store.acquire_lock("investigation", 120, "other") is True
    report = sched.run_cycle()
    assert report.skipped_locked is True
    store.release_lock("investigation", "other")


def test_retention_preserves_case_linked_events(store, config):
    _seed_attack(store)
    sched = InvestigationScheduler(config, store, evidence_dir=config.storage.path + ".ev")
    sched.run_cycle()
    before = store.count_events()
    # Aggressive retention: 0-hour raw window would delete low-risk events, but
    # case-linked events must survive.
    sched.config.storage.raw_event_retention_hours = 0
    sched.config.storage.medium_risk_retention_days = 0
    sched.config.storage.high_risk_retention_days = 0
    deleted = sched.apply_retention()
    after = store.count_events()
    assert after <= before
    # At least the case-linked events remain.
    assert after >= 1
    assert isinstance(deleted, dict)
