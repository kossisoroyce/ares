"""Build bounded case packages from sequences and dedupe them (spec 18).

The case builder converts a scored :class:`Sequence` plus its supporting
findings into the case package handed to the investigator (spec 18.1). Cases
are deduplicated by host + ancestry + destination + rules + time window so
repeated activity updates one case instead of producing endless alerts
(spec 18.2).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from ares.config import Config
from ares.correlation import Sequence
from ares.detection.engine import DetectionResult
from ares.events.ids import new_case_id
from ares.storage import Store


def _iso(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).isoformat(timespec="milliseconds")


def _priority(score: float) -> str:
    if score >= 0.95:
        return "critical"
    if score >= 0.80:
        return "high"
    if score >= 0.60:
        return "medium"
    return "low"


class CaseBuilder:
    def __init__(self, store: Store, config: Config) -> None:
        self._store = store
        self._config = config

    def _dedup_key(self, seq: Sequence, findings: list[DetectionResult]) -> str:
        """Stable behavioural identity for a case (spec 18.2).

        Keys on *what happened* — the executables, destinations and persistence
        mechanisms in a time window — rather than on which rules fired. Some
        rules (e.g. first-seen destination) only trigger on the first
        occurrence, so keying on rule ids would make otherwise-identical repeat
        activity spawn new cases instead of updating the existing one.
        """
        exes = sorted(
            {
                (n.event.get("executable") or n.event.get("name") or "")
                for n in seq.nodes
                if n.event.type.startswith("process.")
            }
        )
        dests = sorted(
            {n.event.get("destination") or "" for n in seq.nodes if n.event.get("destination")}
        )
        persistence = sorted(
            {
                n.event.get("path") or ""
                for n in seq.nodes
                if (n.event.get("path") or "").startswith(("/etc/cron", "/etc/systemd"))
                or "authorized_keys" in (n.event.get("path") or "")
            }
        )
        # 5-minute window bucket so recurring activity collapses.
        window = seq.start_ns // (5 * 60 * 1_000_000_000)
        material = "|".join(
            [seq.host_id, ",".join(exes), ",".join(dests), ",".join(persistence), str(window)]
        )
        return hashlib.sha256(material.encode()).hexdigest()[:24]

    def build(self, seq: Sequence, findings: list[DetectionResult]) -> tuple[dict, bool]:
        """Create or update a case for ``seq``.

        Returns ``(case, is_new)``.
        """
        dedup_key = self._dedup_key(seq, findings)
        existing = self._store.find_case_by_dedup(dedup_key)

        summary = self._summarize(seq, findings)
        title = self._title(seq, findings)
        priority = _priority(seq.score)

        if existing:
            case = {
                "case_id": existing["case_id"],
                "host_id": seq.host_id,
                "title": title,
                "summary": summary,
                "risk_score": max(existing.get("risk_score", 0.0), seq.score),
                "priority": priority,
                "status": existing.get("status", "open"),
                "dedup_key": dedup_key,
                "package": self._package(existing["case_id"], seq, findings, summary, title),
                "increment_hit": 1,
            }
            self._store.upsert_case(case)
            self._store.link_case_events(existing["case_id"], seq.event_ids)
            return case, False

        case_id = new_case_id()
        package = self._package(case_id, seq, findings, summary, title)
        case = {
            "case_id": case_id,
            "host_id": seq.host_id,
            "title": title,
            "summary": summary,
            "risk_score": seq.score,
            "priority": priority,
            "status": "open",
            "dedup_key": dedup_key,
            "package": package,
        }
        self._store.upsert_case(case)
        self._store.link_case_events(case_id, seq.event_ids)
        # Attach findings to the case.
        for dr in findings:
            row = dr.finding.to_row()
            row["case_id"] = case_id
            self._store.write_finding(row)
        return case, True

    def _title(self, seq: Sequence, findings: list[DetectionResult]) -> str:
        if findings:
            return max(findings, key=lambda d: d.finding.risk_score).finding.title
        return f"Suspicious activity sequence ({len(seq.nodes)} events)"

    def _summarize(self, seq: Sequence, findings: list[DetectionResult]) -> str:
        parts = seq.reasons[:4]
        if not parts and findings:
            parts = findings[0].finding.reasons
        return "; ".join(parts) or "Correlated suspicious activity."

    def _package(
        self,
        case_id: str,
        seq: Sequence,
        findings: list[DetectionResult],
        summary: str,
        title: str,
    ) -> dict:
        """The bounded case package handed to the investigator (spec 18.1)."""
        return {
            "case_id": case_id,
            "host": {
                "id": seq.host_id,
                "role": self._config.host.role,
                "environment": self._config.host.environment,
                "criticality": self._config.host.criticality,
            },
            "window": {"start": _iso(seq.start_ns), "end": _iso(seq.end_ns)},
            "summary": summary,
            "title": title,
            "risk_score": seq.score,
            "sequence": [
                {
                    "relationship": n.relationship,
                    "event_type": n.event.type,
                    "label": n.label,
                    "event_id": n.event.event_id,
                    "process_id": n.event.process_id,
                    "payload": n.event.payload,
                }
                for n in seq.nodes
            ],
            "sequence_render": seq.render(),
            "supporting_findings": [
                {
                    "rule_id": dr.finding.rule_id,
                    "title": dr.finding.title,
                    "severity": dr.finding.severity,
                    "reasons": dr.finding.reasons,
                }
                for dr in findings
            ],
            "baseline_context": {},
            "deployment_context": {},
            "previous_related_cases": [],
            "available_tools": [],
            "data_policy": {
                "send_raw_logs_to_model": self._config.privacy.send_raw_logs_to_model,
                "send_file_contents_to_model": self._config.privacy.send_file_contents_to_model,
            },
        }
