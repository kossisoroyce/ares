"""Filesystem integrity watcher for protected paths (spec 7.3).

Uses ``watchdog`` when available for event-driven monitoring; otherwise falls
back to a periodic stat-based poller. Emits file.create / file.modify /
file.delete / file.permission_change events. Only high-value protected paths are
watched to bound cost (spec 10 enrichment budgeting).
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from pathlib import Path

from ares.events import Event, EventType
from ares.sensors.base import EventCallback, Sensor, SensorCapabilities
from ares.sensors.host import HostIdentity

try:
    from watchdog.events import FileSystemEventHandler  # type: ignore
    from watchdog.observers import Observer  # type: ignore

    _HAVE_WATCHDOG = True
except Exception:  # pragma: no cover
    _HAVE_WATCHDOG = False


def _expand_paths(patterns: list[str]) -> list[str]:
    """Expand glob patterns (e.g. /home/*/.ssh) to existing directories/files."""
    out: list[str] = []
    for pat in patterns:
        if any(ch in pat for ch in "*?["):
            from glob import glob

            out.extend(glob(pat))
        elif os.path.exists(pat):
            out.append(pat)
    return out


class FilesystemSensor(Sensor):
    name = "filesystem"

    def __init__(
        self,
        emit: EventCallback,
        host: HostIdentity,
        protected_paths: list[str],
        ignored_paths: list[str] | None = None,
        poll_interval: float = 2.0,
    ) -> None:
        super().__init__(emit, poll_interval)
        self._host = host
        self._protected = protected_paths
        self._ignored = ignored_paths or []
        self._observer = None
        self._snapshot: dict[str, tuple[float, int, int]] = {}  # path -> (mtime, size, mode)

    def available(self) -> bool:
        return bool(_expand_paths(self._protected))

    def capabilities(self) -> SensorCapabilities:
        return SensorCapabilities(filesystem_integrity=True)

    def _ignored_path(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, f"{ig}*") or path.startswith(ig) for ig in self._ignored)

    def _emit_file_event(self, etype: EventType, path: str, extra: dict | None = None) -> None:
        payload = {"path": path, "protected": True}
        st = None
        try:
            st = os.stat(path)
            payload.update(
                {
                    "size": st.st_size,
                    "permissions": oct(st.st_mode & 0o777),
                    "owner_uid": st.st_uid,
                    "is_executable": bool(st.st_mode & 0o111),
                }
            )
        except OSError:
            pass
        if extra:
            payload.update(extra)
        self._emit(
            Event(
                host_id=self._host.host_id,
                boot_id=self._host.boot_id,
                event_type=etype,
                source="filesystem",
                severity_hint=0.3,
                payload=payload,
            )
        )

    # -- watchdog path -----------------------------------------------------

    def run(self) -> None:
        if _HAVE_WATCHDOG:
            self._run_watchdog()
        else:
            super().run()  # polling fallback

    def _run_watchdog(self) -> None:
        sensor = self

        class _Handler(FileSystemEventHandler):  # type: ignore
            def on_created(self, event):
                if not event.is_directory and not sensor._ignored_path(event.src_path):
                    sensor._emit_file_event(EventType.FILE_CREATE, event.src_path)

            def on_deleted(self, event):
                if not event.is_directory and not sensor._ignored_path(event.src_path):
                    sensor._emit_file_event(EventType.FILE_DELETE, event.src_path)

            def on_modified(self, event):
                if not event.is_directory and not sensor._ignored_path(event.src_path):
                    sensor._emit_file_event(EventType.FILE_MODIFY, event.src_path)

            def on_moved(self, event):
                if not sensor._ignored_path(event.src_path):
                    sensor._emit_file_event(
                        EventType.FILE_RENAME,
                        event.dest_path,
                        {"from_path": event.src_path},
                    )

        self._observer = Observer()
        for path in _expand_paths(self._protected):
            try:
                self._observer.schedule(_Handler(), path, recursive=True)
            except Exception:
                continue
        self._observer.start()
        try:
            while not self._stop.wait(0.5):
                pass
        finally:
            self._observer.stop()
            self._observer.join(timeout=5)

    # -- polling fallback --------------------------------------------------

    def poll(self) -> Iterator[Event]:
        events: list[Event] = []
        current: dict[str, tuple[float, int, int]] = {}
        for root in _expand_paths(self._protected):
            p = Path(root)
            files = [p] if p.is_file() else p.rglob("*") if p.is_dir() else []
            for f in files:
                sf = str(f)
                if self._ignored_path(sf):
                    continue
                try:
                    st = f.stat()
                    if not os.path.isfile(sf):
                        continue
                    sig = (st.st_mtime, st.st_size, st.st_mode & 0o777)
                except OSError:
                    continue
                current[sf] = sig
                prev = self._snapshot.get(sf)
                if prev is None:
                    if self._snapshot:  # not first scan
                        self._emit_file_event(EventType.FILE_CREATE, sf)
                elif prev != sig:
                    if prev[2] != sig[2]:
                        self._emit_file_event(
                            EventType.FILE_PERMISSION_CHANGE,
                            sf,
                            {"old_mode": oct(prev[2]), "new_mode": oct(sig[2])},
                        )
                    else:
                        self._emit_file_event(EventType.FILE_MODIFY, sf)
        for old in set(self._snapshot) - set(current):
            self._emit_file_event(EventType.FILE_DELETE, old)
        self._snapshot = current
        return iter(events)
