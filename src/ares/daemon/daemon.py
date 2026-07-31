"""The continuous telemetry daemon (spec 6.1).

Loads sensors, receives events continuously, redacts + enriches them, batches
writes to the store, and runs the low-latency streaming detector. Findings that
hit the immediate critical path (spec 13) trigger volatile evidence capture
before the suspicious process can disappear.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from pathlib import Path

from ares.baseline import BaselineEngine
from ares.config import Config
from ares.correlation import Correlator  # noqa: F401 (used by scheduler; imported for parity)
from ares.detection import DetectionEngine
from ares.detection.engine import DetectionResult
from ares.enrichment import EnrichmentPipeline
from ares.events import Event
from ares.notifications import NotificationManager
from ares.notifications.base import Notification
from ares.redaction import Redactor
from ares.response import ResponseEngine
from ares.sensors import build_sensors, detect_host_identity
from ares.sensors.base import SensorCapabilities
from ares.storage import Store
from ares.telemetry import HealthMetrics

log = logging.getLogger("ares.daemon")


class Daemon:
    def __init__(self, config: Config, store: Store | None = None) -> None:
        self.config = config
        self.host = detect_host_identity()
        self.store = store or Store(config.storage.path)
        self.metrics = HealthMetrics()
        self.redactor = Redactor()
        self.enricher = EnrichmentPipeline(config)
        self.baseline = BaselineEngine(
            store=self.store, learning_period_days=config.detection.learning_period_days
        )
        self.notifications = NotificationManager(config)
        self._evidence_dir = str(Path(config.storage.path).parent / "evidence")
        self.response = ResponseEngine(self.store, config, self._evidence_dir)

        self._queue: queue.Queue[Event] = queue.Queue(maxsize=config.daemon.event_buffer_size)
        self._stop = threading.Event()
        self._writer_thread: threading.Thread | None = None

        self.detector = DetectionEngine(
            self.store,
            host_role=config.host.role,
            environment=config.host.environment,
            immediate_threshold=config.detection.immediate_alert_threshold,
            on_immediate=self._handle_immediate,
        )
        self.sensors = build_sensors(config, self.host, self._emit, self.redactor)
        self._capabilities = SensorCapabilities()
        for s in self.sensors:
            self._capabilities = self._capabilities.merge(s.capabilities())

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self.store.upsert_host(
            self.host.host_id,
            self.config.host.role,
            self.config.host.environment,
            self.config.host.criticality,
        )
        self.store.record_boot(self.host.boot_id, self.host.host_id)
        self.store.record_sensor_health(self._capabilities.as_dict())
        log.info(
            "host=%s boot=%s capabilities=%s",
            self.host.host_id,
            self.host.boot_id,
            self._capabilities.as_dict(),
        )

        self._writer_thread = threading.Thread(target=self._writer_loop, name="writer", daemon=True)
        self._writer_thread.start()
        for sensor in self.sensors:
            sensor.start()
            log.info("sensor started: %s", sensor.name)

    def stop(self) -> None:
        self._stop.set()
        for sensor in self.sensors:
            sensor.stop()
        if self._writer_thread:
            self._writer_thread.join(timeout=5)
        self._flush_remaining()

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(1.0):
                pass
        except KeyboardInterrupt:  # pragma: no cover
            pass
        finally:
            self.stop()

    # -- event ingress -----------------------------------------------------

    def _emit(self, event: Event) -> None:
        """Sensor callback. Redaction of argv already happens in the sensor;
        here we enrich and enqueue. Applies backpressure by dropping when the
        buffer is full and counting the drop (spec 25.2 storage-unavailable)."""
        self.metrics.incr("events_received")
        event = self.enricher.enrich(event)
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.metrics.incr("events_dropped")

    def _writer_loop(self) -> None:
        batch: list[Event] = []
        flush_interval = self.config.daemon.flush_interval_ms / 1000.0
        last_flush = time.monotonic()
        while not self._stop.is_set() or not self._queue.empty():
            timeout = max(0.01, flush_interval)
            try:
                event = self._queue.get(timeout=timeout)
                batch.append(event)
            except queue.Empty:
                pass
            now = time.monotonic()
            if batch and (
                len(batch) >= self.config.daemon.batch_size or now - last_flush >= flush_interval
            ):
                self._process_batch(batch)
                batch = []
                last_flush = now
        if batch:
            self._process_batch(batch)

    def _process_batch(self, batch: list[Event]) -> None:
        written = self.store.write_events(batch)
        self.metrics.incr("events_written", written)
        for event in batch:
            results = self.detector.evaluate(event)
            if results:
                self.metrics.incr("findings_created", len(results))
            high_risk = any(r.finding.risk_score >= 0.6 for r in results)
            # Fold into baseline unless high-risk (poisoning protection, spec 17.4).
            self.baseline.observe(event, high_risk=high_risk)

    def _flush_remaining(self) -> None:
        remaining: list[Event] = []
        while True:
            try:
                remaining.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if remaining:
            self._process_batch(remaining)

    # -- immediate critical path (spec 13) --------------------------------

    def _handle_immediate(self, result: DetectionResult) -> None:
        self.metrics.incr("immediate_alerts")
        finding = result.finding
        event = result.event
        # Volatile evidence capture BEFORE the process disappears (spec 14).
        pid = event.get("pid")
        if pid is not None:
            self.response._executor.execute("capture_process_state", {"pid": pid})  # noqa: SLF001
        exe = event.get("executable")
        if exe:
            self.response._executor.execute("hash_file", {"path": exe})  # noqa: SLF001
        # Freeze the baseline during an active critical incident (spec 17.4).
        self.baseline.freeze(True)

        if self.config.response.mode.__str__() != "observe":
            self.notifications.notify(
                Notification(
                    title=f"IMMEDIATE: {finding.title}",
                    body="; ".join(finding.reasons),
                    severity=finding.severity,
                )
            )

    # -- health ------------------------------------------------------------

    def capabilities(self) -> dict:
        return self._capabilities.as_dict()

    def health(self) -> dict:
        snap = self.metrics.snapshot()
        snap.update(
            {
                "host_id": self.host.host_id,
                "boot_id": self.host.boot_id,
                "sensors": [s.name for s in self.sensors],
                "capabilities": self.capabilities(),
                "db_size_bytes": self.store.db_size_bytes(),
                "queue_depth": self._queue.qsize(),
            }
        )
        return snap
