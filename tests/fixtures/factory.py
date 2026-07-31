"""Event factory helpers for building test/simulation event sequences."""

from __future__ import annotations

import itertools

from ares.events import Event, EventType, process_identity

_counter = itertools.count(1)

HOST = "host_test"
BOOT = "boot_test"


def _ts() -> int:
    # Monotonically increasing, spaced ~20ms apart in ns.
    return 1_785_449_655_000_000 + next(_counter) * 20_000_000


def exec_event(
    executable: str,
    *,
    name: str | None = None,
    argv: list[str] | None = None,
    uid: int = 0,
    pid: int | None = None,
    parent_id: str | None = None,
    parent_name: str | None = None,
    parent_is_network_service: bool = False,
) -> Event:
    pid = pid or (4000 + next(_counter))
    started = _ts()
    return Event(
        host_id=HOST,
        boot_id=BOOT,
        timestamp_ns=started,
        event_type=EventType.PROCESS_EXEC,
        source="test",
        process_id=process_identity(HOST, BOOT, pid, started),
        user_id=f"uid:{uid}",
        payload={
            "pid": pid,
            "executable": executable,
            "name": name or executable.rsplit("/", 1)[-1],
            "argv": argv or [executable],
            "uid": uid,
            "started_at_ns": started,
            "parent_id": parent_id,
            "parent_name": parent_name,
            "parent_is_network_service": parent_is_network_service,
        },
    )


def connect_event(destination: str, *, external: bool = True, pid: int = 4100) -> Event:
    ip, _, port = destination.rpartition(":")
    return Event(
        host_id=HOST,
        boot_id=BOOT,
        timestamp_ns=_ts(),
        event_type=EventType.NETWORK_CONNECT,
        source="test",
        process_id=process_identity(HOST, BOOT, pid, 1),
        payload={
            "destination": destination,
            "destination_address": ip,
            "destination_port": int(port) if port.isdigit() else 0,
            "is_external": external,
            "pid": pid,
        },
    )


def file_event(event_type: EventType, path: str, *, executable: bool = False) -> Event:
    return Event(
        host_id=HOST,
        boot_id=BOOT,
        timestamp_ns=_ts(),
        event_type=event_type,
        source="test",
        severity_hint=0.3,
        payload={"path": path, "is_executable": executable, "protected": True},
    )


def login_event(event_type: EventType, user: str, source: str) -> Event:
    return Event(
        host_id=HOST,
        boot_id=BOOT,
        timestamp_ns=_ts(),
        event_type=event_type,
        source="test",
        payload={"user": user, "source": source},
    )
