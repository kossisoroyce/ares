"""Stable identity helpers.

A PID alone is insufficient because Linux reuses process IDs (spec 7.1).
Process identity is therefore ``host_id:boot_id:pid:process_start_timestamp``.
"""

from __future__ import annotations

import time

try:
    import ulid  # type: ignore

    def _ulid() -> str:
        return ulid.new().str

except Exception:  # pragma: no cover - fallback when ulid-py missing
    import uuid

    def _ulid() -> str:
        return uuid.uuid4().hex.upper()


def new_id(prefix: str) -> str:
    """Return a prefixed, sortable identifier, e.g. ``evt_01JXX...``."""
    return f"{prefix}_{_ulid()}"


def new_event_id() -> str:
    return new_id("evt")


def new_finding_id() -> str:
    return new_id("find")


def new_case_id() -> str:
    return new_id("case")


def new_action_id() -> str:
    return new_id("act")


def new_investigation_id() -> str:
    return new_id("inv")


def process_identity(host_id: str, boot_id: str, pid: int, started_at_ns: int) -> str:
    """Build a reuse-safe process identity string (spec 7.1)."""
    return f"{host_id}:{boot_id}:{pid}:{started_at_ns}"


def now_ns() -> int:
    """Wall-clock nanoseconds for reporting."""
    return time.time_ns()


def monotonic_ns() -> int:
    """Monotonic nanoseconds for internal ordering (spec 25.2 clock change)."""
    return time.monotonic_ns()
