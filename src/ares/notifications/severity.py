"""Severity ordering shared by notification routing (spec §21, §27)."""

from __future__ import annotations

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def meets_threshold(severity: str, threshold: str) -> bool:
    """True when ``severity`` is at or above ``threshold``."""
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)
