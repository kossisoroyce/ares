"""Identity/auth event sensor via auth log tailing (spec 7.4, Linux only).

A pragmatic first-release collector that tails ``/var/log/auth.log`` (Debian/
Ubuntu) or ``/var/log/secure`` (RHEL family) and extracts login success/failure
and sudo events. On systems using journald exclusively this should be replaced
by a journald reader; the interface is identical.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from pathlib import Path

from ares.events import Event, EventType
from ares.sensors.base import EventCallback, Sensor, SensorCapabilities
from ares.sensors.host import HostIdentity

_AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure"]

_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
_ACCEPTED = re.compile(r"Accepted \S+ for (\S+) from (\S+)")
_NEW_USER = re.compile(r"new user: name=(\S+?),")
_SUDO = re.compile(r"sudo:\s+(\S+) :.*COMMAND=(\S+)")


class IdentitySensor(Sensor):
    name = "identity.audit"

    def __init__(self, emit: EventCallback, host: HostIdentity, poll_interval: float = 2.0) -> None:
        super().__init__(emit, poll_interval)
        self._host = host
        self._path = next((p for p in _AUTH_LOGS if Path(p).exists()), None)
        self._offset = 0
        if self._path:
            try:
                self._offset = Path(self._path).stat().st_size
            except OSError:
                self._offset = 0

    def available(self) -> bool:
        return self._path is not None

    def capabilities(self) -> SensorCapabilities:
        return SensorCapabilities(audit_fallback=True)

    def _event(self, etype: EventType, payload: dict, severity: float) -> Event:
        return Event(
            host_id=self._host.host_id,
            boot_id=self._host.boot_id,
            event_type=etype,
            source="audit",
            severity_hint=severity,
            user_id=f"user:{payload.get('user')}" if payload.get("user") else None,
            payload=payload,
        )

    def poll(self) -> Iterator[Event]:
        if not self._path:
            return
        try:
            size = Path(self._path).stat().st_size
            if size < self._offset:  # rotated
                self._offset = 0
            with open(self._path, errors="replace") as fh:
                fh.seek(self._offset)
                lines = fh.readlines()
                self._offset = fh.tell()
        except OSError:
            return

        for line in lines:
            if m := _FAILED.search(line):
                yield self._event(
                    EventType.IDENTITY_LOGIN_FAILED,
                    {"user": m.group(1), "source": m.group(2), "ts": time.time()},
                    0.4,
                )
            elif m := _ACCEPTED.search(line):
                yield self._event(
                    EventType.IDENTITY_LOGIN,
                    {"user": m.group(1), "source": m.group(2)},
                    0.2,
                )
            elif m := _NEW_USER.search(line):
                yield self._event(EventType.IDENTITY_USER_CREATED, {"user": m.group(1)}, 0.7)
            elif m := _SUDO.search(line):
                yield self._event(
                    EventType.PRIVILEGE_CHANGE,
                    {"user": m.group(1), "command": m.group(2), "via": "sudo"},
                    0.3,
                )
