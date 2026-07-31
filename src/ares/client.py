"""High-level Python API facade (spec section 28)."""

from __future__ import annotations

from pathlib import Path

from ares.config import Config, load_config
from ares.scheduler import InvestigationScheduler
from ares.sensors import detect_host_identity
from ares.storage import Store


class _FindingsAPI:
    def __init__(self, store: Store) -> None:
        self._store = store

    def list(self, severity: str | None = None, status: str | None = None) -> list[dict]:
        return self._store.list_findings(severity=severity, status=status)


class _CasesAPI:
    def __init__(self, store: Store, scheduler: InvestigationScheduler) -> None:
        self._store = store
        self._scheduler = scheduler

    def list(self, status: str | None = None) -> list[dict]:
        return self._store.list_cases(status=status)

    def show(self, case_id: str) -> dict | None:
        case = self._store.get_case(case_id)
        if case is not None:
            case["verdicts"] = self._store.verdicts_for_case(case_id)
        return case

    def investigate(self, case_id: str) -> dict:
        case = self._store.get_case(case_id)
        if not case:
            raise KeyError(case_id)
        verdict = self._scheduler.investigator.investigate_case(case)
        self._scheduler._act_on_verdict(case_id, verdict)  # noqa: SLF001
        return verdict.model_dump()

    def close(self, case_id: str) -> None:
        self._store.set_case_status(case_id, "closed")

    def feedback(
        self, case_id: str, label: str, note: str | None = None, scope: str = "host"
    ) -> None:
        self._store.add_feedback(case_id=case_id, label=label, note=note, scope=scope)


class _ActionsAPI:
    def __init__(self, scheduler: InvestigationScheduler) -> None:
        self._response = scheduler.response
        self._store = scheduler.store

    def list(self, status: str | None = None) -> list[dict]:
        return self._store.list_actions(status=status)

    def approve(self, action_id: str) -> dict:
        return self._response.approve(action_id)

    def reject(self, action_id: str) -> None:
        self._response.reject(action_id)

    def rollback(self, action_id: str) -> dict:
        return self._response.rollback(action_id)


class Ares:
    """Facade tying the store, scheduler and sub-APIs together."""

    def __init__(self, config: Config, store: Store | None = None) -> None:
        self.config = config
        self.store = store or Store(config.storage.path)
        self.host = detect_host_identity()
        evidence_dir = str(Path(config.storage.path).parent / "evidence")
        self.scheduler = InvestigationScheduler(config, self.store, evidence_dir=evidence_dir)
        self.findings = _FindingsAPI(self.store)
        self.cases = _CasesAPI(self.store, self.scheduler)
        self.actions = _ActionsAPI(self.scheduler)

    @classmethod
    def from_config(cls, path: str | None = None) -> Ares:
        return cls(load_config(path))

    def status(self) -> dict:
        health = self.store.latest_sensor_health() or {}
        open_cases = self.store.list_cases(status="open")
        watermark = self.store.get_state("watermark") or {}
        return {
            "host_id": self.host.host_id,
            "boot_id": self.host.boot_id,
            "mode": getattr(self.config.response.mode, "value", self.config.response.mode),
            "ai_provider": self.config.investigation.model_provider,
            "notification_channels": self.scheduler.notifications.channels,
            "event_count": self.store.count_events(),
            "open_cases": len(open_cases),
            "critical_cases": len([c for c in open_cases if c.get("priority") == "critical"]),
            "capabilities": health.get("capabilities", {}),
            "db_size_bytes": self.store.db_size_bytes(),
            "last_watermark": watermark.get("updated_at"),
            "baseline": self.store.baseline_summary(),
        }

    def investigate_now(self) -> dict:
        report = self.scheduler.run_cycle()
        return {
            "events_processed": report.events_processed,
            "sequences": report.sequences,
            "cases_created": report.cases_created,
            "cases_updated": report.cases_updated,
            "investigations": report.investigations,
            "skipped_locked": report.skipped_locked,
        }

    def doctor(self) -> dict:
        """Self-check for common problems (spec 26.3 `ares doctor`)."""
        checks = {
            "storage_writable": True,
            "integrity_ok": self.store.integrity_check(),
            "config_valid": True,
        }
        try:
            self.store.set_state("doctor", {"ok": True})
        except Exception:
            checks["storage_writable"] = False
        return checks

    def close(self) -> None:
        self.store.close()
