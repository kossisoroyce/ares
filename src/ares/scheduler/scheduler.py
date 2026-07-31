"""Investigation scheduler: the one-minute cycle (spec 15).

Each cycle: acquire a lock, read unprocessed events past the watermark,
correlate into sequences, score, build/dedupe cases, enforce budgets, run the
investigator on the top cases, persist verdicts, plan responses, notify, then
advance the watermark and release the lock. Overlap is prevented with a lease
lock so a long cycle never spawns a duplicate worker (spec 15.3).
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass

from ares.cases import CaseBuilder
from ares.config import Config
from ares.correlation import Correlator
from ares.detection import DetectionEngine
from ares.detection.engine import DetectionResult
from ares.investigator import Investigator
from ares.notifications import NotificationManager
from ares.notifications.base import Notification
from ares.response import ResponseEngine
from ares.storage import Store
from ares.telemetry import HealthMetrics

log = logging.getLogger("ares.scheduler")

LOCK_NAME = "investigation"


@dataclass
class CycleReport:
    events_processed: int = 0
    sequences: int = 0
    cases_created: int = 0
    cases_updated: int = 0
    investigations: int = 0
    skipped_locked: bool = False
    verdicts: list[dict] | None = None

    def __post_init__(self) -> None:
        if self.verdicts is None:
            self.verdicts = []


class InvestigationScheduler:
    def __init__(
        self,
        config: Config,
        store: Store,
        metrics: HealthMetrics | None = None,
        evidence_dir: str | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.metrics = metrics or HealthMetrics()
        self.correlator = Correlator(store, host_role=config.host.role)
        self.case_builder = CaseBuilder(store, config)
        self.investigator = Investigator(store, config)
        self.response = ResponseEngine(
            store, config, evidence_dir or config.storage.path + ".evidence"
        )
        self.notifications = NotificationManager(config)
        # A detector instance to (re)derive findings for the batch during the
        # cycle. Findings written by the daemon already exist; here we align
        # findings to the correlated sequence.
        self._detector = DetectionEngine(
            store, host_role=config.host.role, environment=config.host.environment
        )

    # -- watermark ---------------------------------------------------------

    def _watermark(self) -> int:
        state = self.store.get_state("watermark")
        return state.get("last_event_timestamp_ns", 0) if state else 0

    def _advance_watermark(self, ts_ns: int, event_id: str) -> None:
        from datetime import datetime, timezone

        self.store.set_state(
            "watermark",
            {
                "last_event_timestamp_ns": ts_ns,
                "last_event_id": event_id,
                "updated_at": datetime.now(timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z"),
            },
        )

    # -- the cycle ---------------------------------------------------------

    def run_cycle(self) -> CycleReport:
        owner = uuid.uuid4().hex
        ttl = max(self.config.investigation.timeout_seconds * 2, 120)
        if not self.store.acquire_lock(LOCK_NAME, ttl, owner):
            log.info("investigation cycle skipped: another cycle holds the lock")
            return CycleReport(skipped_locked=True)

        t0 = time.monotonic()
        report = CycleReport()
        try:
            events = self.store.unprocessed_events(limit=5000)
            report.events_processed = len(events)
            if not events:
                return report

            # Re-run detection to attach findings to this batch's sequences.
            findings: list[DetectionResult] = []
            for e in events:
                findings.extend(self._detector.evaluate(e))

            sequences = self.correlator.correlate(events, findings)
            report.sequences = len(sequences)

            # Build candidate cases above the investigation threshold, ranked.
            candidates = [s for s in sequences if s.score >= self.config.detection.retain_threshold]
            investigate_score = self.config.detection.investigation_threshold
            budget = self.config.investigation.max_cases_per_cycle
            investigated = 0

            findings_by_seq = self._group_findings(sequences, findings)

            for seq in candidates:
                case, is_new = self.case_builder.build(seq, findings_by_seq.get(seq.key, []))
                if is_new:
                    report.cases_created += 1
                else:
                    report.cases_updated += 1

                if seq.score >= investigate_score and investigated < budget:
                    full_case = self.store.get_case(case["case_id"]) or case
                    verdict = self.investigator.investigate_case(full_case)
                    investigated += 1
                    self.metrics.incr("investigations_run")
                    report.investigations += 1
                    report.verdicts.append(  # type: ignore[union-attr]
                        {"case_id": case["case_id"], "verdict": verdict.model_dump()}
                    )
                    self._act_on_verdict(case["case_id"], verdict)

            # Advance watermark and mark processed.
            last = max(events, key=lambda e: e.timestamp_ns)
            self._advance_watermark(last.timestamp_ns, last.event_id)
            self.store.mark_processed([e.event_id for e in events])

            self.metrics.last_investigation_at = time.time()
            self.metrics.scheduler_lag_seconds = max(
                0.0, (time.monotonic() - t0) - self.config.investigation.interval_seconds
            )
            return report
        finally:
            self.store.release_lock(LOCK_NAME, owner)

    def _group_findings(self, sequences, findings: list[DetectionResult]) -> dict:
        out: dict[str, list[DetectionResult]] = {}
        event_to_seq: dict[str, str] = {}
        for seq in sequences:
            for eid in seq.event_ids:
                event_to_seq[eid] = seq.key
        for dr in findings:
            for eid in dr.finding.event_ids:
                key = event_to_seq.get(eid)
                if key:
                    out.setdefault(key, []).append(dr)
                    break
        return out

    def _act_on_verdict(self, case_id: str, verdict) -> None:
        # Plan/execute responses per policy and notify (spec 22, 27).
        self.response.plan_from_verdict(case_id, verdict)
        if verdict.classification in {"suspicious", "likely_malicious", "malicious"}:
            self.notifications.notify(
                Notification(
                    title=verdict.title or "Investigation verdict",
                    body=verdict.summary,
                    severity=verdict.severity,
                    case_id=case_id,
                )
            )

    # -- retention maintenance --------------------------------------------

    def apply_retention(self) -> dict:
        s = self.config.storage
        return self.store.apply_retention(
            raw_hours=s.raw_event_retention_hours,
            medium_days=s.medium_risk_retention_days,
            high_days=s.high_risk_retention_days,
            case_days=s.case_event_retention_days,
        )
