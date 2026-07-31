"""Linked entity/event sequence model (spec 16.1)."""

from __future__ import annotations

from dataclasses import dataclass, field

from ares.events import Event

RELATIONSHIPS = (
    "spawned",
    "created",
    "modified",
    "executed",
    "connected_to",
    "authenticated_as",
    "elevated_to",
    "persisted_via",
    "loaded",
    "deleted",
    "deployed_by",
    "belongs_to",
)


@dataclass
class SequenceNode:
    event: Event
    relationship: str = ""

    @property
    def label(self) -> str:
        e = self.event
        if e.type.startswith("process."):
            return f"{e.get('name') or e.get('executable') or 'process'}"
        if e.type.startswith("network."):
            return f"connect {e.get('destination') or e.get('listening_port')}"
        if e.type.startswith("file."):
            return f"{e.type.split('.')[1]} {e.get('path')}"
        return e.type


@dataclass
class Sequence:
    """A correlated chain of events sharing a lineage (spec 16.2)."""

    key: str  # correlation key (e.g. process lineage root)
    host_id: str
    nodes: list[SequenceNode] = field(default_factory=list)
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    @property
    def event_ids(self) -> list[str]:
        return [n.event.event_id for n in self.nodes]

    @property
    def start_ns(self) -> int:
        return min((n.event.timestamp_ns for n in self.nodes), default=0)

    @property
    def end_ns(self) -> int:
        return max((n.event.timestamp_ns for n in self.nodes), default=0)

    def render(self) -> str:
        """Human-readable indented tree (spec 16.2 example / 31.3 timeline)."""
        lines = []
        for depth, node in enumerate(self.nodes):
            indent = "  " * depth
            arrow = "└── " if depth else ""
            lines.append(f"{indent}{arrow}{node.label}")
        return "\n".join(lines)
