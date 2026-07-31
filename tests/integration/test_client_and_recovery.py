"""Client facade + recovery/durability tests (spec 25.2, 28, 35.2)."""

from ares import Ares
from ares.events import EventType
from ares.storage import Store
from tests.fixtures.factory import connect_event, exec_event, file_event


def _seed(store):
    store.write_events(
        [
            exec_event("/bin/sh", name="sh", parent_name="nginx", parent_is_network_service=True),
            file_event(EventType.FILE_CREATE, "/tmp/.cache-x", executable=True),
            exec_event("/tmp/.cache-x"),
            connect_event("203.0.113.20:443"),
        ]
    )


def test_client_status_and_investigate(config):
    client = Ares(config)
    _seed(client.store)
    client.investigate_now()
    status = client.status()
    assert status["event_count"] == 4
    assert status["open_cases"] >= 0
    cases = client.cases.list()
    assert cases
    detail = client.cases.show(cases[0]["case_id"])
    assert "verdicts" in detail
    client.close()


def test_watermark_survives_restart(config):
    """A fresh scheduler continues from the durable watermark (spec 25.2)."""
    client = Ares(config)
    _seed(client.store)
    client.investigate_now()
    wm1 = client.store.get_state("watermark")
    client.close()

    # Simulate daemon restart: new store on the same DB file.
    store2 = Store(config.storage.path)
    wm2 = store2.get_state("watermark")
    assert wm2 == wm1
    store2.close()


def test_doctor_checks(config):
    client = Ares(config)
    checks = client.doctor()
    assert checks["integrity_ok"] is True
    assert checks["storage_writable"] is True
    client.close()


def test_feedback_recorded(config):
    client = Ares(config)
    _seed(client.store)
    client.investigate_now()
    case_id = client.cases.list()[0]["case_id"]
    client.cases.feedback(case_id, "false_positive", note="known scanner")
    with client.store._lock:
        row = client.store._conn.execute(
            "SELECT label FROM feedback WHERE case_id=?", (case_id,)
        ).fetchone()
    assert row["label"] == "false_positive"
    client.close()
