"""Investigator orchestrator with budgets and audit logging (spec 19.2)."""

from __future__ import annotations

from datetime import datetime, timezone

from ares.config import Config
from ares.events.ids import new_investigation_id
from ares.investigator.providers import get_provider
from ares.investigator.tools import InvestigatorTools
from ares.investigator.verdict import Verdict
from ares.storage import Store


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Investigator:
    """Runs a bounded investigation for a single case and persists the verdict."""

    def __init__(self, store: Store, config: Config) -> None:
        self._store = store
        self._config = config
        inv = config.investigation
        self._provider = get_provider(inv.model_provider, inv.model)
        self._budget = {
            "max_tool_calls": inv.max_tool_calls_per_case,
            "max_output_tokens": inv.max_output_tokens,
            "max_input_tokens": inv.max_input_tokens,
            "timeout_seconds": inv.timeout_seconds,
        }

    def investigate_case(self, case: dict) -> Verdict:
        package = case.get("package", {})
        case_id = case["case_id"]
        tools = InvestigatorTools(
            store=self._store,
            host_id=case["host_id"],
            allow_file_contents=self._config.privacy.send_file_contents_to_model,
        )
        investigation_id = new_investigation_id()
        started = _utcnow()

        verdict, usage = self._provider.investigate(package, tools, self._budget)

        self._store.write_investigation(
            {
                "investigation_id": investigation_id,
                "case_id": case_id,
                "started_at": started,
                "finished_at": _utcnow(),
                "provider": self._provider.name,
                "model": self._config.investigation.model,
                "tool_calls": usage.get("tool_calls", tools.call_count),
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
                "audit_log": tools.audit_log,
            }
        )
        self._store.write_verdict(investigation_id, case_id, verdict.model_dump())
        # Reflect the verdict severity/priority back onto the case.
        self._store.upsert_case(
            {
                "case_id": case_id,
                "host_id": case["host_id"],
                "title": verdict.title or case.get("title"),
                "summary": verdict.summary or case.get("summary"),
                "risk_score": max(case.get("risk_score", 0.0), verdict.confidence),
                "priority": self._priority_from(verdict),
                "status": "investigated",
                "package": package,
            }
        )
        return verdict

    @staticmethod
    def _priority_from(verdict: Verdict) -> str:
        if verdict.severity in {"critical"}:
            return "critical"
        if verdict.severity == "high":
            return "high"
        if verdict.severity == "medium":
            return "medium"
        return "low"

    @property
    def elapsed_budget_seconds(self) -> int:
        return self._budget["timeout_seconds"]
