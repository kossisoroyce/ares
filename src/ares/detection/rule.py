"""Rule base classes and the Finding result type (spec 12.3, 28.1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ares.events import Event
from ares.events.ids import new_finding_id
from ares.events.schema import _utcnow_iso

if TYPE_CHECKING:
    from ares.storage import Store


@dataclass
class RuleContext:
    """Context handed to a rule during evaluation.

    Gives rules read access to the store for ancestry/baseline lookups plus a
    small amount of per-evaluation scratch state, without letting a rule mutate
    the pipeline. Rules should stay cheap; expensive lookups belong in the
    investigator (spec 6.3 vs 6.6).
    """

    store: Store
    host_role: str = "generic"
    environment: str = "production"

    def parent_process(self, event: Event) -> dict[str, Any] | None:
        parent_id = event.get("parent_id")
        if not parent_id:
            return None
        return self.store.get_process(parent_id)


@dataclass
class Finding:
    """A deterministic detection result (spec 12.3)."""

    title: str
    severity: str = "medium"
    risk_score: float = 0.5
    confidence: float = 0.8
    reasons: list[str] = field(default_factory=list)
    rule_id: str = ""
    immediate: bool = False
    finding_id: str = field(default_factory=new_finding_id)
    created_at: str = field(default_factory=_utcnow_iso)
    event_ids: list[str] = field(default_factory=list)
    primary_process_id: str | None = None
    host_id: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "created_at": self.created_at,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "host_id": self.host_id,
            "primary_process_id": self.primary_process_id,
            "event_ids": self.event_ids,
            "reasons": self.reasons,
            "immediate": int(self.immediate),
            "status": "open",
        }


class Rule:
    """Base class for streaming rules (spec 12.1).

    Subclasses set ``rule_id`` and implement :meth:`evaluate`, returning a
    :class:`Finding` when the rule matches or ``None`` otherwise. Rules are
    evaluated on every event in arrival order.
    """

    rule_id: str = "BASE_RULE"
    title: str = "rule"
    #: default severity for findings produced by this rule
    severity: str = "medium"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        raise NotImplementedError

    # Helper used by many subclasses.
    def _finding(self, event: Event, **kwargs: Any) -> Finding:
        f = Finding(
            title=kwargs.pop("title", self.title),
            severity=kwargs.pop("severity", self.severity),
            rule_id=self.rule_id,
            host_id=event.host_id,
            primary_process_id=event.process_id,
            event_ids=[event.event_id],
            **kwargs,
        )
        return f
