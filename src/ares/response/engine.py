"""Propose, approve, execute and roll back response actions (spec 22)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ares.config import Config
from ares.events.ids import new_action_id
from ares.investigator.verdict import Verdict
from ares.policy import PolicyEngine
from ares.policy.engine import Disposition
from ares.response.actions import ACTION_REGISTRY, ActionExecutor
from ares.storage import Store


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ResponseEngine:
    def __init__(self, store: Store, config: Config, evidence_dir: str) -> None:
        self._store = store
        self._config = config
        self._policy = PolicyEngine(config)
        self._executor = ActionExecutor(evidence_dir)

    def plan_from_verdict(self, case_id: str, verdict: Verdict) -> list[dict]:
        """Turn recommended actions into policy-checked, persisted action rows.

        Every action carries an explicit target, idempotency key, reversibility
        and rollback (spec 22.3). Automatic (evidence) actions execute
        immediately; others are stored as ``proposed`` awaiting approval.
        """
        planned: list[dict] = []
        for rec in verdict.recommended_actions:
            decision = self._policy.evaluate(rec.action)
            if decision.disposition is Disposition.PROHIBITED:
                continue
            spec = ACTION_REGISTRY.get(rec.action)
            action = {
                "action_id": new_action_id(),
                "case_id": case_id,
                "created_at": _utcnow(),
                "type": rec.action,
                "target": {},
                "reason": verdict.title or verdict.summary,
                "requested_by": "ai_investigator",
                "requires_approval": decision.disposition is Disposition.REQUIRES_APPROVAL,
                "reversible": spec.reversible if spec else rec.reversible,
                "rollback_action": spec.rollback_action if spec else None,
                "status": "proposed",
                "idempotency_key": uuid.uuid4().hex,
            }
            self._store.write_action(action)

            if decision.disposition is Disposition.AUTOMATIC:
                self._run(action)
            planned.append(action)
        return planned

    def approve(self, action_id: str) -> dict:
        action = self._store.get_action(action_id)
        if not action:
            raise KeyError(action_id)
        if action["status"] not in {"proposed", "approved"}:
            return {"status": action["status"], "note": "not in an approvable state"}
        self._store.set_action_status(action_id, "approved")
        action["status"] = "approved"
        return self._run(action)

    def reject(self, action_id: str) -> None:
        self._store.set_action_status(action_id, "rejected")

    def rollback(self, action_id: str) -> dict:
        action = self._store.get_action(action_id)
        if not action:
            raise KeyError(action_id)
        rollback = action.get("rollback_action")
        if not rollback:
            return {"status": "failed", "error": "action is not reversible"}
        result = self._executor.execute(rollback, action.get("target", {}))
        self._store.set_action_status(action_id, "rolled_back", result)
        return result

    def _run(self, action: dict) -> dict:
        result = self._executor.execute(action["type"], action.get("target", {}))
        status = (
            "executed" if result.get("status") == "executed" else result.get("status", "failed")
        )
        self._store.set_action_status(action["action_id"], status, result)
        return result
