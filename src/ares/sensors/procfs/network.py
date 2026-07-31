"""Network connection sensor using psutil (spec 7.2).

Polls active connections and emits ``network.connect`` for newly observed
outbound connections and ``network.accept`` for new inbound (listening-side)
connections. On Linux with eBPF this is replaced by kernel network hooks that
also capture failed and very short-lived connections (spec 8.1).
"""

from __future__ import annotations

from collections.abc import Iterator

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

from ares.events import Event, EventType, process_identity
from ares.sensors.base import EventCallback, Sensor, SensorCapabilities
from ares.sensors.host import HostIdentity

_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "::1", "fe80:", "fc", "fd")


def _is_private(addr: str) -> bool:
    if addr.startswith("172."):
        try:
            second = int(addr.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return addr.startswith(_PRIVATE_PREFIXES)


class NetworkSensor(Sensor):
    name = "network.procfs"

    def __init__(
        self,
        emit: EventCallback,
        host: HostIdentity,
        poll_interval: float = 1.0,
    ) -> None:
        super().__init__(emit, poll_interval)
        self._host = host
        self._seen: set[tuple] = set()

    def available(self) -> bool:
        return psutil is not None

    def capabilities(self) -> SensorCapabilities:
        return SensorCapabilities(extras={"network_poll": True})

    def poll(self) -> Iterator[Event]:
        if psutil is None:
            return
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:  # requires elevated perms on some platforms
            return
        for c in conns:
            if not c.raddr and c.status != psutil.CONN_LISTEN:
                continue
            key = (c.pid, c.laddr, c.raddr, c.status)
            if key in self._seen:
                continue
            self._seen.add(key)

            if c.status == psutil.CONN_LISTEN:
                yield self._listen_event(c)
            elif c.raddr:
                yield self._connect_event(c)

    def _proc_ident(self, pid: int | None) -> str | None:
        if pid is None:
            return None
        try:
            p = psutil.Process(pid)
            started_ns = int(p.create_time() * 1_000_000_000)
            return process_identity(self._host.host_id, self._host.boot_id, pid, started_ns)
        except Exception:
            return None

    def _connect_event(self, c) -> Event:
        raddr = f"{c.raddr.ip}:{c.raddr.port}"
        payload = {
            "protocol": "tcp" if c.type == 1 else "udp",
            "source_address": c.laddr.ip if c.laddr else None,
            "source_port": c.laddr.port if c.laddr else None,
            "destination_address": c.raddr.ip,
            "destination_port": c.raddr.port,
            "destination": raddr,
            "result": c.status,
            "is_external": not _is_private(c.raddr.ip),
            "pid": c.pid,
        }
        return Event(
            host_id=self._host.host_id,
            boot_id=self._host.boot_id,
            event_type=EventType.NETWORK_CONNECT,
            source="procfs",
            process_id=self._proc_ident(c.pid),
            payload=payload,
        )

    def _listen_event(self, c) -> Event:
        payload = {
            "protocol": "tcp" if c.type == 1 else "udp",
            "source_address": c.laddr.ip if c.laddr else None,
            "listening_port": c.laddr.port if c.laddr else None,
            "pid": c.pid,
        }
        return Event(
            host_id=self._host.host_id,
            boot_id=self._host.boot_id,
            event_type=EventType.NETWORK_ACCEPT,
            source="procfs",
            process_id=self._proc_ident(c.pid),
            payload=payload,
        )
