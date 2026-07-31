"""Sensor abstraction and capability reporting."""

from __future__ import annotations

import abc
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from ares.events import Event

EventCallback = Callable[[Event], None]


@dataclass
class SensorCapabilities:
    """Enabled capabilities reported at startup (spec 8.3)."""

    ebpf_process_events: bool = False
    ebpf_network_events: bool = False
    filesystem_integrity: bool = False
    audit_fallback: bool = False
    container_enrichment: bool = False
    dns_enrichment: bool = False
    extras: dict[str, bool] = field(default_factory=dict)

    def as_dict(self) -> dict[str, bool]:
        base = {
            "ebpf_process_events": self.ebpf_process_events,
            "ebpf_network_events": self.ebpf_network_events,
            "filesystem_integrity": self.filesystem_integrity,
            "audit_fallback": self.audit_fallback,
            "container_enrichment": self.container_enrichment,
            "dns_enrichment": self.dns_enrichment,
        }
        base.update(self.extras)
        return base

    def merge(self, other: SensorCapabilities) -> SensorCapabilities:
        merged = SensorCapabilities(
            ebpf_process_events=self.ebpf_process_events or other.ebpf_process_events,
            ebpf_network_events=self.ebpf_network_events or other.ebpf_network_events,
            filesystem_integrity=self.filesystem_integrity or other.filesystem_integrity,
            audit_fallback=self.audit_fallback or other.audit_fallback,
            container_enrichment=self.container_enrichment or other.container_enrichment,
            dns_enrichment=self.dns_enrichment or other.dns_enrichment,
        )
        merged.extras = {**self.extras, **other.extras}
        return merged


class Sensor(abc.ABC):  # noqa: B024 - subclasses override poll() or run(); no abstractmethod by design
    """Base class for all sensors.

    Sensors run on their own thread and push :class:`Event` objects to the
    daemon via a callback. Polling sensors implement :meth:`poll`; the base
    class provides the thread lifecycle. Push/streaming sensors (eBPF) may
    override :meth:`run` directly.
    """

    name: str = "sensor"

    def __init__(self, emit: EventCallback, poll_interval: float = 1.0) -> None:
        self._emit = emit
        self._poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def capabilities(self) -> SensorCapabilities:
        return SensorCapabilities()

    def available(self) -> bool:
        """Whether this sensor can run in the current environment."""
        return True

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run_guarded, name=self.name, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run_guarded(self) -> None:
        try:
            self.run()
        except Exception:  # pragma: no cover - defensive; a sensor crash must not kill the daemon
            import logging

            logging.getLogger("ares.sensor").exception("sensor %s crashed", self.name)

    def run(self) -> None:
        """Default loop: repeatedly call :meth:`poll` until stopped."""
        while not self._stop.wait(0):
            for event in self.poll():
                self._emit(event)
            if self._stop.wait(self._poll_interval):
                break

    def poll(self) -> Iterator[Event]:  # pragma: no cover - overridden by polling sensors
        return iter(())
