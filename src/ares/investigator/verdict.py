"""Structured verdict schema (spec 19.4)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Classification = Literal[
    "benign",
    "likely_benign",
    "suspicious",
    "likely_malicious",
    "malicious",
    "unknown",
]


class Evidence(BaseModel):
    claim: str
    supporting_event_ids: list[str] = Field(default_factory=list)
    strength: Literal["weak", "moderate", "strong"] = "moderate"


class BenignExplanation(BaseModel):
    explanation: str
    likelihood: float = 0.0
    contradictions: list[str] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    action: str
    urgency: Literal["low", "medium", "high", "immediate"] = "medium"
    reversible: bool = True
    requires_approval: bool = False


class Verdict(BaseModel):
    classification: Classification = "unknown"
    confidence: float = 0.0
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    title: str = ""
    summary: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    benign_explanations: list[BenignExplanation] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)

    def model_dump_json_safe(self) -> dict:
        return self.model_dump()
