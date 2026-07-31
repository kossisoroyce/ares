"""Streaming detection engine (spec 12).

Evaluates every event against the active rule set, applies suppressions, writes
findings, and reports which findings hit the immediate critical path (spec 13).
"""

from __future__ import annotations

import fnmatch
import logging
from collections.abc import Callable
from dataclasses import dataclass

from ares.detection.builtin import BUILTIN_RULES
from ares.detection.rule import Finding, Rule, RuleContext
from ares.events import Event
from ares.storage import Store

log = logging.getLogger("ares.detection")


@dataclass
class DetectionResult:
    finding: Finding
    event: Event
    immediate: bool


class DetectionEngine:
    def __init__(
        self,
        store: Store,
        rules: list[Rule] | None = None,
        host_role: str = "generic",
        environment: str = "production",
        immediate_threshold: float = 0.90,
        on_immediate: Callable[[DetectionResult], None] | None = None,
    ) -> None:
        self._store = store
        self._rules = rules if rules is not None else list(BUILTIN_RULES)
        self._context = RuleContext(store=store, host_role=host_role, environment=environment)
        self._immediate_threshold = immediate_threshold
        self._on_immediate = on_immediate

    @property
    def rules(self) -> list[Rule]:
        return self._rules

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def evaluate(self, event: Event) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for rule in self._rules:
            try:
                finding = rule.evaluate(event, self._context)
            except Exception:  # a broken rule must not stop detection
                log.exception("rule %s raised", getattr(rule, "rule_id", rule))
                continue
            if finding is None:
                continue
            if self._suppressed(finding, event):
                continue
            immediate = finding.immediate or finding.risk_score >= self._immediate_threshold
            finding.immediate = immediate
            self._store.write_finding(finding.to_row())
            result = DetectionResult(finding=finding, event=event, immediate=immediate)
            results.append(result)
            if immediate and self._on_immediate:
                try:
                    self._on_immediate(result)
                except Exception:
                    log.exception("immediate handler failed for %s", finding.finding_id)
        return results

    def _suppressed(self, finding: Finding, event: Event) -> bool:
        """Apply active suppression rules (spec 12.1, 21)."""
        for supp in self._store.active_suppressions():
            m = supp["matcher"]
            if "rule_id" in m and m["rule_id"] != finding.rule_id:
                continue
            if "host_id" in m and m["host_id"] != event.host_id:
                continue
            if "path_glob" in m:
                path = event.get("path") or ""
                if not fnmatch.fnmatch(path, m["path_glob"]):
                    continue
            if "executable" in m and event.get("executable") != m["executable"]:
                continue
            return True
        return False
