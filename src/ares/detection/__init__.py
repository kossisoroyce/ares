"""Streaming detection engine (spec section 12)."""

from ares.detection.builtin import BUILTIN_RULES
from ares.detection.engine import DetectionEngine
from ares.detection.rule import Finding, Rule, RuleContext

__all__ = ["Finding", "Rule", "RuleContext", "DetectionEngine", "BUILTIN_RULES"]
