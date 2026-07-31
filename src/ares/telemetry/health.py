"""In-memory health signals for the daemon and scheduler (spec 25.1)."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class HealthMetrics:
    started_at: float = field(default_factory=time.time)
    events_received: int = 0
    events_written: int = 0
    events_dropped: int = 0
    findings_created: int = 0
    immediate_alerts: int = 0
    investigations_run: int = 0
    last_investigation_at: float | None = None
    scheduler_lag_seconds: float = 0.0
    ai_provider_available: bool = True
    notifications_healthy: bool = True
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def incr(self, field_name: str, by: int = 1) -> None:
        with self._lock:
            setattr(self, field_name, getattr(self, field_name) + by)

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.started_at

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "uptime_seconds": round(self.uptime_seconds, 1),
                "events_received": self.events_received,
                "events_written": self.events_written,
                "events_dropped": self.events_dropped,
                "findings_created": self.findings_created,
                "immediate_alerts": self.immediate_alerts,
                "investigations_run": self.investigations_run,
                "last_investigation_at": self.last_investigation_at,
                "scheduler_lag_seconds": round(self.scheduler_lag_seconds, 2),
                "ai_provider_available": self.ai_provider_available,
                "notifications_healthy": self.notifications_healthy,
            }
