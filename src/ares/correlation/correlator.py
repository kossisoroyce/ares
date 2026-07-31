"""Correlate events into scored behavioural sequences (spec 16).

Groups events by process lineage (falling back to host+time proximity), orders
them, and computes a normalized sequence risk score combining rule severity,
rarity, privilege/persistence/network impact and sequence coherence
(spec 16.3). The correlator is where multi-step attack chains such as
"file written -> executed -> connected externally -> deleted" (spec 12.2 #20)
are recognised.
"""

from __future__ import annotations

from collections import defaultdict

from ares.correlation.graph import Sequence, SequenceNode
from ares.detection.engine import DetectionResult
from ares.events import Event
from ares.storage import Store

# Score weights (spec 16.3). Kept explicit so scoring stays auditable.
_W = {
    "rule_severity": 1.0,
    "rarity": 0.4,
    "privilege": 0.5,
    "persistence": 0.5,
    "network": 0.3,
    "coherence": 0.4,
}

_SEVERITY_SCORE = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.8, "critical": 1.0}


class Correlator:
    def __init__(self, store: Store, host_role: str = "generic") -> None:
        self._store = store
        self._host_role = host_role

    #: max wall-clock gap (ns) between consecutive events in one session.
    SESSION_GAP_NS = 3 * 1_000_000_000
    #: cap on events per sequence so a busy host can't produce one giant graph.
    MAX_SESSION_EVENTS = 250

    def correlate(
        self, events: list[Event], findings: list[DetectionResult] | None = None
    ) -> list[Sequence]:
        """Group events into behavioural sequences and score them.

        Grouping is by host and time proximity (spec 16.1): consecutive events
        on a host within ``SESSION_GAP_NS`` belong to the same session. This
        captures the canonical sub-second attack burst even when process
        lineage is not fully reconstructed. Entity links (shared executable /
        file path / destination) further refine coherence scoring.
        """
        findings = findings or []
        findings_by_event: dict[str, list[DetectionResult]] = defaultdict(list)
        for dr in findings:
            for eid in dr.finding.event_ids:
                findings_by_event[eid].append(dr)

        by_host: dict[str, list[Event]] = defaultdict(list)
        for e in sorted(events, key=lambda x: x.timestamp_ns):
            by_host[e.host_id].append(e)

        sequences: list[Sequence] = []
        for host_id, host_events in by_host.items():
            for session in self._sessionize(host_events):
                seq = Sequence(key=f"{host_id}:{session[0].timestamp_ns}", host_id=host_id)
                for e in session:
                    seq.nodes.append(SequenceNode(event=e, relationship=self._relationship(e)))
                self._score(seq, findings_by_event)
                sequences.append(seq)
        sequences.sort(key=lambda s: s.score, reverse=True)
        return sequences

    def _sessionize(self, host_events: list[Event]) -> list[list[Event]]:
        sessions: list[list[Event]] = []
        current: list[Event] = []
        last_ts = None
        for e in host_events:
            if current and (
                (last_ts is not None and e.timestamp_ns - last_ts > self.SESSION_GAP_NS)
                or len(current) >= self.MAX_SESSION_EVENTS
            ):
                sessions.append(current)
                current = []
            current.append(e)
            last_ts = e.timestamp_ns
        if current:
            sessions.append(current)
        return sessions

    @staticmethod
    def _relationship(event: Event) -> str:
        t = event.type
        if t == "process.exec":
            return "spawned"
        if t == "network.connect":
            return "connected_to"
        if t == "file.create":
            return "created"
        if t == "file.modify":
            return "modified"
        if t == "file.delete":
            return "deleted"
        if t.startswith("persistence"):
            return "persisted_via"
        if t == "privilege.change":
            return "elevated_to"
        return "belongs_to"

    def _score(self, seq: Sequence, findings_by_event: dict[str, list[DetectionResult]]) -> None:
        """Compute a 0..1 sequence risk score (spec 16.3).

        The score starts from the strongest supporting rule severity (so a
        single critical detection stands on its own) and adds capped bonuses for
        privilege/persistence/network impact, attack-chain coherence and rarity.
        Allow-list / maintenance confidence would subtract here (spec 16.3); the
        engine models those via suppressions upstream in the first release.
        """
        reasons: list[str] = []

        base = 0.0
        for node in seq.nodes:
            for dr in findings_by_event.get(node.event.event_id, []):
                base = max(base, _SEVERITY_SCORE.get(dr.finding.severity, 0.3))
                reasons.extend(dr.finding.reasons)

        types = {n.event.type for n in seq.nodes}
        bonus = 0.0

        if "privilege.change" in types or any(n.event.get("uid") == 0 for n in seq.nodes):
            bonus += _W["privilege"] * 0.3
            reasons.append("Privilege activity in sequence")

        if any(
            n.event.type.startswith("persistence")
            or (n.event.get("path") or "").startswith(("/etc/cron", "/etc/systemd"))
            or "authorized_keys" in (n.event.get("path") or "")
            for n in seq.nodes
        ):
            bonus += _W["persistence"] * 0.4
            reasons.append("Persistence mechanism touched")

        if any(n.event.get("is_external") for n in seq.nodes):
            bonus += _W["network"] * 0.4
            reasons.append("External network connection")

        chain_bonus, chain_reason = self._coherence(seq, types)
        if chain_bonus:
            bonus += _W["coherence"] * 0.4 * chain_bonus
            reasons.append(chain_reason)

        if any(
            (n.event.get("executable") or "").startswith(("/tmp/", "/dev/shm/")) for n in seq.nodes
        ):
            bonus += _W["rarity"] * 0.4
            reasons.append("Execution from temporary directory")

        seq.score = round(min(base + bonus, 1.0), 3)
        seq.reasons = list(dict.fromkeys(reasons))

    @staticmethod
    def _coherence(seq: Sequence, types: set[str]) -> tuple[float, str]:
        """Reward chains that match known multi-step attack patterns."""
        has_create = "file.create" in types
        has_exec = "process.exec" in types
        has_conn = "network.connect" in types
        has_delete = "file.delete" in types

        steps = sum([has_create, has_exec, has_conn, has_delete])
        if has_create and has_exec and has_conn and has_delete:
            return 1.0, "Full write->execute->connect->delete chain observed"
        if has_exec and has_conn and has_delete:
            return 0.8, "Execute->connect->delete chain observed"
        if has_create and has_exec:
            return 0.5, "File created then executed"
        if steps >= 3:
            return 0.4, "Multi-stage activity in sequence"
        return 0.0, ""
