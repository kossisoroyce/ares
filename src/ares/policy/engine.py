"""Decide whether a response action is prohibited/allowed/needs approval (spec 6.7, 22)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ares.config import Config
from ares.config.models import ResponseMode
from ares.response.actions import ACTION_REGISTRY


class Disposition(str, Enum):
    PROHIBITED = "prohibited"
    AUTOMATIC = "automatic"
    REQUIRES_APPROVAL = "requires_approval"


@dataclass
class PolicyDecision:
    action_type: str
    disposition: Disposition
    reason: str

    @property
    def allowed(self) -> bool:
        return self.disposition != Disposition.PROHIBITED


class PolicyEngine:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._resp = config.response

    def evaluate(self, action_type: str) -> PolicyDecision:
        """Classify an action per config lists and the active response mode."""
        if action_type in self._resp.prohibited:
            return PolicyDecision(
                action_type, Disposition.PROHIBITED, "action is on the prohibited list"
            )

        mode = self._resp.mode

        # Evidence-category actions are read-only and safe in every mode
        # (spec 13.2, 22.1) — allow them automatically whether they were listed
        # explicitly or not.
        spec = ACTION_REGISTRY.get(action_type)
        is_evidence = spec is not None and spec.category == "evidence"

        # Observe/alert/recommend/approve modes never execute containment.
        if mode in {
            ResponseMode.OBSERVE,
            ResponseMode.ALERT,
            ResponseMode.RECOMMEND,
            ResponseMode.APPROVE,
        }:
            if action_type in self._resp.automatic_actions or is_evidence:
                return PolicyDecision(
                    action_type, Disposition.AUTOMATIC, "allow-listed evidence action"
                )
            return PolicyDecision(
                action_type,
                Disposition.REQUIRES_APPROVAL,
                f"{mode} mode requires operator approval",
            )

        # Automatic mode: only narrowly allow-listed (or evidence) actions run
        # without approval.
        if action_type in self._resp.automatic_actions or is_evidence:
            return PolicyDecision(
                action_type, Disposition.AUTOMATIC, "allow-listed for automatic execution"
            )
        if action_type in self._resp.approval_required:
            return PolicyDecision(
                action_type, Disposition.REQUIRES_APPROVAL, "requires approval by policy"
            )
        # Default deny-to-approval for anything unclassified.
        return PolicyDecision(
            action_type, Disposition.REQUIRES_APPROVAL, "unclassified action defaults to approval"
        )
