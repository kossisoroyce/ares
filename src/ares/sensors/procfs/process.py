"""Process execution/exit sensor using psutil (spec 7.1).

This is the compatibility-fallback collector (spec 8.2). It polls the process
table and diffs snapshots to emit ``process.exec`` and ``process.exit`` events.
On Linux with eBPF this sensor is replaced by the kernel-level collector, which
captures short-lived processes the poller can miss; the polling sensor is still
useful for development on macOS and as a degraded fallback.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

from ares.events import Event, EventType, process_identity
from ares.redaction import Redactor
from ares.sensors.base import EventCallback, Sensor, SensorCapabilities
from ares.sensors.host import HostIdentity

_NETWORK_SERVICE_NAMES = {
    "nginx",
    "apache2",
    "httpd",
    "sshd",
    "postgres",
    "mysqld",
    "mariadbd",
    "redis-server",
    "node",
    "gunicorn",
    "uwsgi",
    "java",
    "php-fpm",
}


class ProcessSensor(Sensor):
    name = "process.procfs"

    def __init__(
        self,
        emit: EventCallback,
        host: HostIdentity,
        redactor: Redactor,
        poll_interval: float = 0.5,
        include_arguments: str = "redacted",
    ) -> None:
        super().__init__(emit, poll_interval)
        self._host = host
        self._redactor = redactor
        self._include_args = include_arguments
        self._known: dict[int, str] = {}  # pid -> process_id
        self._proc_meta: dict[int, dict] = {}
        # The first poll seeds the baseline of already-running processes without
        # emitting execs for them (they did not execute during our watch). Only
        # processes that appear after startup are reported. The eBPF collector
        # does not need this because it observes actual execve() calls.
        self._seeded = False

    def available(self) -> bool:
        return psutil is not None

    def capabilities(self) -> SensorCapabilities:
        return SensorCapabilities(extras={"process_poll": True})

    def _identity(self, proc: psutil.Process) -> tuple[str, dict]:
        started_ns = int(proc.create_time() * 1_000_000_000)
        pid = proc.pid
        pident = process_identity(self._host.host_id, self._host.boot_id, pid, started_ns)
        try:
            argv = list(proc.cmdline())
        except Exception:
            argv = []
        try:
            exe = proc.exe()
        except Exception:
            exe = proc.name()
        try:
            ppid = proc.ppid()
        except Exception:
            ppid = None
        try:
            uid = proc.uids().real
        except Exception:
            uid = None
        try:
            cwd = proc.cwd()
        except Exception:
            cwd = None
        try:
            name = proc.name()
        except Exception:
            name = ""

        if self._include_args == "none":
            argv_out, removed = [], []
        elif self._include_args == "full":
            argv_out, removed = argv, []
        else:
            argv_out, removed = self._redactor.redact_argv(argv)

        meta = {
            "process_id": pident,
            "pid": pid,
            "ppid": ppid,
            "executable": exe,
            "name": name,
            "argv": argv_out,
            "uid": uid,
            "working_directory": cwd,
            "started_at_ns": started_ns,
            "redacted_fields": removed,
        }
        return pident, meta

    def poll(self) -> Iterator[Event]:
        if psutil is None:
            return
        current: dict[int, str] = {}
        for proc in psutil.process_iter():
            try:
                pid = proc.pid
                pident, meta = self._identity(proc)
            except Exception:
                continue
            current[pid] = pident
            if self._known.get(pid) == pident:
                continue  # already reported this exact process
            newly_seen = self._known.get(pid) != pident
            self._known[pid] = pident
            self._proc_meta[pid] = meta
            if self._seeded and newly_seen:
                yield self._exec_event(meta)

        # Detect exits (only after the baseline seed).
        for pid, pident in list(self._known.items()):
            if pid not in current:
                meta = self._proc_meta.pop(pid, {"process_id": pident, "pid": pid})
                del self._known[pid]
                if self._seeded:
                    yield self._exit_event(meta)

        self._seeded = True

    def _parent_id(self, meta: dict) -> str | None:
        ppid = meta.get("ppid")
        return self._known.get(ppid) if ppid is not None else None

    def _exec_event(self, meta: dict) -> Event:
        parent = self._proc_meta.get(meta.get("ppid"), {}) if meta.get("ppid") else {}
        parent_name = parent.get("name", "")
        payload = {
            "pid": meta["pid"],
            "ppid": meta.get("ppid"),
            "executable": meta.get("executable"),
            "name": meta.get("name"),
            "argv": meta.get("argv"),
            "uid": meta.get("uid"),
            "effective_uid": meta.get("uid"),
            "working_directory": meta.get("working_directory"),
            "started_at_ns": meta.get("started_at_ns"),
            "parent_id": self._parent_id(meta),
            "parent_executable": parent.get("executable"),
            "parent_name": parent_name,
            "parent_is_network_service": parent_name in _NETWORK_SERVICE_NAMES,
        }
        from ares.events import Redaction

        return Event(
            host_id=self._host.host_id,
            boot_id=self._host.boot_id,
            timestamp_ns=meta.get("started_at_ns") or time.time_ns(),
            event_type=EventType.PROCESS_EXEC,
            source="procfs",
            process_id=meta["process_id"],
            user_id=f"uid:{meta.get('uid')}" if meta.get("uid") is not None else None,
            payload=payload,
            redaction=Redaction(fields_removed=meta.get("redacted_fields", [])),
        )

    def _exit_event(self, meta: dict) -> Event:
        return Event(
            host_id=self._host.host_id,
            boot_id=self._host.boot_id,
            event_type=EventType.PROCESS_EXIT,
            source="procfs",
            process_id=meta["process_id"],
            payload={"pid": meta.get("pid")},
        )
