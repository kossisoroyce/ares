"""Storage layer tests (spec 23, 35.1)."""

from tests.fixtures.factory import connect_event, exec_event


def test_write_and_read_events(store):
    events = [exec_event("/bin/ls"), exec_event("/tmp/.x")]
    assert store.write_events(events) == 2
    assert store.count_events() == 2
    unprocessed = store.unprocessed_events()
    assert len(unprocessed) == 2
    store.mark_processed([unprocessed[0].event_id])
    assert len(store.unprocessed_events()) == 1


def test_first_seen_destination(store):
    assert store.observe_destination("h", "1.2.3.4:443") is True
    assert store.observe_destination("h", "1.2.3.4:443") is False


def test_process_ancestry(store):
    root = exec_event("/usr/sbin/nginx", pid=100)
    store.upsert_process(
        {"process_id": root.process_id, "host_id": "h", "pid": 100, "executable": "nginx"}
    )
    child = exec_event("/bin/sh", pid=101, parent_id=root.process_id)
    store.upsert_process(
        {
            "process_id": child.process_id,
            "host_id": "h",
            "pid": 101,
            "parent_id": root.process_id,
            "executable": "/bin/sh",
        }
    )
    chain = store.process_ancestry(child.process_id)
    assert [p["executable"] for p in chain] == ["/bin/sh", "nginx"]


def test_lock_prevents_overlap(store):
    assert store.acquire_lock("cycle", 60, "owner-a") is True
    assert store.acquire_lock("cycle", 60, "owner-b") is False
    store.release_lock("cycle", "owner-a")
    assert store.acquire_lock("cycle", 60, "owner-b") is True


def test_watermark_roundtrip(store):
    store.set_state("watermark", {"last_event_timestamp_ns": 42})
    assert store.get_state("watermark")["last_event_timestamp_ns"] == 42


def test_baseline_counts(store):
    assert store.observe_baseline("d", "k") == 1
    assert store.observe_baseline("d", "k") == 2
    assert store.baseline_count("d", "k") == 2


def test_integrity_check(store):
    store.write_events([connect_event("8.8.8.8:53")])
    assert store.integrity_check() is True
