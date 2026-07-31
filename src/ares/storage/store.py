"""SQLite-backed store with WAL, batched writes and typed helpers (spec 23)."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ares.events import Event

_SCHEMA = (Path(__file__).parent / "schema.sql").read_text()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _risk_band(severity_hint: float) -> str:
    if severity_hint >= 0.6:
        return "high"
    if severity_hint >= 0.3:
        return "medium"
    return "low"


class Store:
    """Thread-safe wrapper over a single SQLite connection.

    A process-wide lock serializes writes; SQLite in WAL mode still allows
    concurrent readers. This is sufficient for the single-host first release
    (spec 23.1) and keeps the daemon and scheduler in one file.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- hosts / boots -----------------------------------------------------

    def upsert_host(self, host_id: str, role: str, environment: str, criticality: str) -> None:
        now = _utcnow()
        with self._lock:
            self._conn.execute(
                """INSERT INTO hosts (host_id, role, environment, criticality, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(host_id) DO UPDATE SET
                     role=excluded.role, environment=excluded.environment,
                     criticality=excluded.criticality, last_seen=excluded.last_seen""",
                (host_id, role, environment, criticality, now, now),
            )

    def record_boot(self, boot_id: str, host_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO boots (boot_id, host_id, booted_at) VALUES (?, ?, ?)",
                (boot_id, host_id, _utcnow()),
            )

    # -- events ------------------------------------------------------------

    def write_events(self, events: Sequence[Event]) -> int:
        if not events:
            return 0
        rows = []
        for e in events:
            rows.append(
                (
                    e.event_id,
                    e.host_id,
                    e.boot_id,
                    e.timestamp_ns,
                    e.received_at,
                    e.type,
                    e.source,
                    e.severity_hint,
                    e.process_id,
                    e.user_id,
                    e.container_id,
                    _risk_band(e.severity_hint),
                    json.dumps(e.payload),
                    json.dumps(e.enrichment),
                    json.dumps(e.redaction.model_dump()),
                )
            )
        with self._lock:
            self._conn.executemany(
                """INSERT OR IGNORE INTO events
                   (event_id, host_id, boot_id, timestamp_ns, received_at, event_type,
                    source, severity_hint, process_id, user_id, container_id, risk_band,
                    payload, enrichment, redaction)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
        return len(rows)

    def _row_to_event(self, row: sqlite3.Row) -> Event:
        return Event(
            event_id=row["event_id"],
            host_id=row["host_id"],
            boot_id=row["boot_id"] or "",
            timestamp_ns=row["timestamp_ns"],
            received_at=row["received_at"],
            event_type=row["event_type"],
            source=row["source"] or "unknown",
            severity_hint=row["severity_hint"],
            process_id=row["process_id"],
            user_id=row["user_id"],
            container_id=row["container_id"],
            payload=json.loads(row["payload"]),
            enrichment=json.loads(row["enrichment"]),
            redaction=json.loads(row["redaction"]),
        )

    def events_since(self, timestamp_ns: int, limit: int = 5000) -> list[Event]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM events WHERE timestamp_ns > ? ORDER BY timestamp_ns ASC LIMIT ?",
                (timestamp_ns, limit),
            )
            return [self._row_to_event(r) for r in cur.fetchall()]

    def unprocessed_events(self, limit: int = 5000) -> list[Event]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM events WHERE processed = 0 ORDER BY timestamp_ns ASC LIMIT ?",
                (limit,),
            )
            return [self._row_to_event(r) for r in cur.fetchall()]

    def mark_processed(self, event_ids: Iterable[str]) -> None:
        ids = list(event_ids)
        if not ids:
            return
        with self._lock:
            self._conn.executemany(
                "UPDATE events SET processed = 1 WHERE event_id = ?", [(i,) for i in ids]
            )

    def get_events(self, event_ids: Sequence[str]) -> list[Event]:
        if not event_ids:
            return []
        placeholders = ",".join("?" * len(event_ids))
        with self._lock:
            cur = self._conn.execute(
                f"SELECT * FROM events WHERE event_id IN ({placeholders})", list(event_ids)
            )
            return [self._row_to_event(r) for r in cur.fetchall()]

    def search_events(
        self,
        *,
        process: str | None = None,
        destination: str | None = None,
        event_type: str | None = None,
        since_ns: int | None = None,
        limit: int = 200,
    ) -> list[Event]:
        clauses: list[str] = []
        params: list[Any] = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if since_ns is not None:
            clauses.append("timestamp_ns >= ?")
            params.append(since_ns)
        if process:
            clauses.append("(payload LIKE ? OR process_id LIKE ?)")
            params.extend([f"%{process}%", f"%{process}%"])
        if destination:
            clauses.append("payload LIKE ?")
            params.append(f"%{destination}%")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            cur = self._conn.execute(
                f"SELECT * FROM events{where} ORDER BY timestamp_ns DESC LIMIT ?",
                [*params, limit],
            )
            return [self._row_to_event(r) for r in cur.fetchall()]

    def count_events(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]

    # -- processes ---------------------------------------------------------

    def upsert_process(self, proc: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO processes
                   (process_id, host_id, pid, ppid, parent_id, executable, exe_hash, argv,
                    uid, started_at_ns, exited_at_ns, container_id)
                   VALUES (:process_id, :host_id, :pid, :ppid, :parent_id, :executable,
                           :exe_hash, :argv, :uid, :started_at_ns, :exited_at_ns, :container_id)
                   ON CONFLICT(process_id) DO UPDATE SET
                     exited_at_ns=COALESCE(excluded.exited_at_ns, processes.exited_at_ns),
                     exe_hash=COALESCE(excluded.exe_hash, processes.exe_hash)""",
                {
                    "process_id": proc["process_id"],
                    "host_id": proc["host_id"],
                    "pid": proc.get("pid"),
                    "ppid": proc.get("ppid"),
                    "parent_id": proc.get("parent_id"),
                    "executable": proc.get("executable"),
                    "exe_hash": proc.get("exe_hash"),
                    "argv": json.dumps(proc.get("argv", [])),
                    "uid": proc.get("uid"),
                    "started_at_ns": proc.get("started_at_ns"),
                    "exited_at_ns": proc.get("exited_at_ns"),
                    "container_id": proc.get("container_id"),
                },
            )

    def get_process(self, process_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM processes WHERE process_id = ?", (process_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["argv"] = json.loads(d["argv"]) if d.get("argv") else []
        return d

    def process_ancestry(self, process_id: str, max_depth: int = 20) -> list[dict[str, Any]]:
        chain: list[dict[str, Any]] = []
        seen: set[str] = set()
        current = process_id
        while current and current not in seen and len(chain) < max_depth:
            seen.add(current)
            proc = self.get_process(current)
            if not proc:
                break
            chain.append(proc)
            current = proc.get("parent_id")
        return chain

    # -- network destinations ---------------------------------------------

    def observe_destination(self, host_id: str, destination: str) -> bool:
        """Record a destination; return True if it was first-seen (spec 12.2 #5)."""
        now = _utcnow()
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM network_destinations WHERE host_id = ? AND destination = ?",
                (host_id, destination),
            ).fetchone()
            if row:
                self._conn.execute(
                    "UPDATE network_destinations SET last_seen=?, seen_count=seen_count+1 WHERE id=?",
                    (now, row["id"]),
                )
                return False
            self._conn.execute(
                """INSERT INTO network_destinations
                   (host_id, destination, first_seen, last_seen, seen_count)
                   VALUES (?, ?, ?, ?, 1)""",
                (host_id, destination, now, now),
            )
            return True

    # -- findings / cases --------------------------------------------------

    def write_finding(self, finding: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO findings
                   (finding_id, created_at, rule_id, title, severity, risk_score, confidence,
                    host_id, primary_process_id, event_ids, reasons, status, immediate, case_id)
                   VALUES (:finding_id, :created_at, :rule_id, :title, :severity, :risk_score,
                           :confidence, :host_id, :primary_process_id, :event_ids, :reasons,
                           :status, :immediate, :case_id)""",
                {
                    **finding,
                    "event_ids": json.dumps(finding.get("event_ids", [])),
                    "reasons": json.dumps(finding.get("reasons", [])),
                    "immediate": int(finding.get("immediate", 0)),
                    "case_id": finding.get("case_id"),
                    "status": finding.get("status", "open"),
                },
            )

    def list_findings(self, severity: str | None = None, status: str | None = None) -> list[dict]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            cur = self._conn.execute(
                f"SELECT * FROM findings{where} ORDER BY created_at DESC LIMIT 500", params
            )
            out = []
            for r in cur.fetchall():
                d = dict(r)
                d["event_ids"] = json.loads(d["event_ids"])
                d["reasons"] = json.loads(d["reasons"])
                out.append(d)
            return out

    def find_case_by_dedup(self, dedup_key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM cases WHERE dedup_key = ?", (dedup_key,)
            ).fetchone()
        return dict(row) if row else None

    def upsert_case(self, case: dict[str, Any]) -> None:
        now = _utcnow()
        with self._lock:
            existing = self._conn.execute(
                "SELECT case_id, hit_count FROM cases WHERE case_id = ?", (case["case_id"],)
            ).fetchone()
            if existing:
                self._conn.execute(
                    """UPDATE cases SET updated_at=?, risk_score=?, priority=?, status=?,
                       summary=?, title=?, package=?, hit_count=hit_count+? WHERE case_id=?""",
                    (
                        now,
                        case.get("risk_score", 0.0),
                        case.get("priority", "medium"),
                        case.get("status", "open"),
                        case.get("summary"),
                        case.get("title"),
                        json.dumps(case.get("package", {})),
                        int(case.get("increment_hit", 0)),
                        case["case_id"],
                    ),
                )
            else:
                self._conn.execute(
                    """INSERT INTO cases
                       (case_id, created_at, updated_at, host_id, title, summary, risk_score,
                        priority, status, dedup_key, package, hit_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (
                        case["case_id"],
                        now,
                        now,
                        case["host_id"],
                        case.get("title"),
                        case.get("summary"),
                        case.get("risk_score", 0.0),
                        case.get("priority", "medium"),
                        case.get("status", "open"),
                        case.get("dedup_key"),
                        json.dumps(case.get("package", {})),
                    ),
                )

    def link_case_events(self, case_id: str, event_ids: Iterable[str]) -> None:
        with self._lock:
            self._conn.executemany(
                "INSERT OR IGNORE INTO case_events (case_id, event_id) VALUES (?, ?)",
                [(case_id, e) for e in event_ids],
            )

    def list_cases(self, status: str | None = None) -> list[dict[str, Any]]:
        where = " WHERE status = ?" if status else ""
        params = [status] if status else []
        with self._lock:
            cur = self._conn.execute(
                f"SELECT * FROM cases{where} ORDER BY risk_score DESC, updated_at DESC", params
            )
            out = []
            for r in cur.fetchall():
                d = dict(r)
                d["package"] = json.loads(d["package"]) if d.get("package") else {}
                out.append(d)
            return out

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["package"] = json.loads(d["package"]) if d.get("package") else {}
        return d

    def set_case_status(self, case_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE cases SET status=?, updated_at=? WHERE case_id=?",
                (status, _utcnow(), case_id),
            )

    # -- investigations / verdicts ----------------------------------------

    def write_investigation(self, inv: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO investigations
                   (investigation_id, case_id, started_at, finished_at, provider, model,
                    tool_calls, input_tokens, output_tokens, audit_log)
                   VALUES (:investigation_id, :case_id, :started_at, :finished_at, :provider,
                           :model, :tool_calls, :input_tokens, :output_tokens, :audit_log)""",
                {**inv, "audit_log": json.dumps(inv.get("audit_log", []))},
            )

    def write_verdict(self, investigation_id: str, case_id: str, verdict: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO verdicts
                   (investigation_id, case_id, created_at, classification, confidence, severity,
                    title, summary, verdict)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    investigation_id,
                    case_id,
                    _utcnow(),
                    verdict.get("classification"),
                    verdict.get("confidence"),
                    verdict.get("severity"),
                    verdict.get("title"),
                    verdict.get("summary"),
                    json.dumps(verdict),
                ),
            )

    def verdicts_for_case(self, case_id: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM verdicts WHERE case_id = ? ORDER BY created_at DESC", (case_id,)
            )
            out = []
            for r in cur.fetchall():
                d = dict(r)
                d["verdict"] = json.loads(d["verdict"])
                out.append(d)
            return out

    # -- actions -----------------------------------------------------------

    def write_action(self, action: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO actions
                   (action_id, case_id, created_at, type, target, reason, requested_by,
                    requires_approval, reversible, rollback_action, status, result)
                   VALUES (:action_id, :case_id, :created_at, :type, :target, :reason,
                           :requested_by, :requires_approval, :reversible, :rollback_action,
                           :status, :result)""",
                {
                    **action,
                    "target": json.dumps(action.get("target", {})),
                    "requires_approval": int(action.get("requires_approval", 1)),
                    "reversible": int(action.get("reversible", 1)),
                    "result": json.dumps(action["result"]) if action.get("result") else None,
                },
            )

    def list_actions(self, status: str | None = None) -> list[dict[str, Any]]:
        where = " WHERE status = ?" if status else ""
        params = [status] if status else []
        with self._lock:
            cur = self._conn.execute(
                f"SELECT * FROM actions{where} ORDER BY created_at DESC", params
            )
            out = []
            for r in cur.fetchall():
                d = dict(r)
                d["target"] = json.loads(d["target"]) if d.get("target") else {}
                d["result"] = json.loads(d["result"]) if d.get("result") else None
                out.append(d)
            return out

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM actions WHERE action_id = ?", (action_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["target"] = json.loads(d["target"]) if d.get("target") else {}
        d["result"] = json.loads(d["result"]) if d.get("result") else None
        return d

    def set_action_status(self, action_id: str, status: str, result: dict | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE actions SET status=?, result=? WHERE action_id=?",
                (status, json.dumps(result) if result else None, action_id),
            )

    # -- baselines ---------------------------------------------------------

    def observe_baseline(self, dimension: str, key: str, frozen: bool = False) -> int:
        """Increment a baseline counter; return the resulting count.

        Skips increment when frozen globally (spec 17.4 poisoning protection)
        is handled by the caller; here we only honor a per-key frozen flag.
        """
        now = _utcnow()
        with self._lock:
            row = self._conn.execute(
                "SELECT id, count, frozen FROM baselines WHERE dimension=? AND key=?",
                (dimension, key),
            ).fetchone()
            if row:
                if row["frozen"]:
                    return row["count"]
                self._conn.execute(
                    "UPDATE baselines SET count=count+1, last_seen=? WHERE id=?",
                    (now, row["id"]),
                )
                return row["count"] + 1
            self._conn.execute(
                """INSERT INTO baselines (dimension, key, count, first_seen, last_seen, frozen)
                   VALUES (?, ?, 1, ?, ?, ?)""",
                (dimension, key, now, now, int(frozen)),
            )
            return 1

    def baseline_count(self, dimension: str, key: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT count FROM baselines WHERE dimension=? AND key=?", (dimension, key)
            ).fetchone()
        return row["count"] if row else 0

    def baseline_summary(self) -> dict[str, int]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT dimension, COUNT(*) AS n FROM baselines GROUP BY dimension"
            )
            return {r["dimension"]: r["n"] for r in cur.fetchall()}

    def freeze_baselines(self, frozen: bool = True) -> None:
        with self._lock:
            self._conn.execute("UPDATE baselines SET frozen=?", (int(frozen),))

    def reset_baselines(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM baselines")

    # -- suppressions / feedback ------------------------------------------

    def add_suppression(
        self, scope: str, matcher: dict, reason: str, expires_at: str | None
    ) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO suppressions (scope, matcher, reason, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (scope, json.dumps(matcher), reason, _utcnow(), expires_at),
            )

    def active_suppressions(self) -> list[dict[str, Any]]:
        now = _utcnow()
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM suppressions WHERE expires_at IS NULL OR expires_at > ?", (now,)
            )
            out = []
            for r in cur.fetchall():
                d = dict(r)
                d["matcher"] = json.loads(d["matcher"])
                out.append(d)
            return out

    def add_feedback(self, **kwargs: Any) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO feedback (finding_id, case_id, label, scope, note, created_at, created_by)
                   VALUES (:finding_id, :case_id, :label, :scope, :note, :created_at, :created_by)""",
                {
                    "finding_id": kwargs.get("finding_id"),
                    "case_id": kwargs.get("case_id"),
                    "label": kwargs["label"],
                    "scope": kwargs.get("scope", "host"),
                    "note": kwargs.get("note"),
                    "created_at": _utcnow(),
                    "created_by": kwargs.get("created_by"),
                },
            )

    # -- scheduler state (watermark + lock) -------------------------------

    def get_state(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM scheduler_state WHERE key = ?", (key,)
            ).fetchone()
        return json.loads(row["value"]) if row else None

    def set_state(self, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO scheduler_state (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (key, json.dumps(value)),
            )

    def acquire_lock(self, name: str, ttl_seconds: int, owner: str) -> bool:
        """Best-effort single-writer lock via a state row with expiry (spec 15.3)."""
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM scheduler_state WHERE key = ?", (f"lock:{name}",)
            ).fetchone()
            if row:
                current = json.loads(row["value"])
                if current.get("expires_at", 0) > now:
                    return False
            self._conn.execute(
                """INSERT INTO scheduler_state (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (f"lock:{name}", json.dumps({"owner": owner, "expires_at": now + ttl_seconds})),
            )
            return True

    def release_lock(self, name: str, owner: str) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM scheduler_state WHERE key = ?", (f"lock:{name}",)
            ).fetchone()
            if row and json.loads(row["value"]).get("owner") == owner:
                self._conn.execute("DELETE FROM scheduler_state WHERE key = ?", (f"lock:{name}",))

    # -- sensor health -----------------------------------------------------

    def record_sensor_health(self, capabilities: dict, metrics: dict | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO sensor_health (reported_at, capabilities, metrics) VALUES (?, ?, ?)",
                (_utcnow(), json.dumps(capabilities), json.dumps(metrics or {})),
            )

    def latest_sensor_health(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sensor_health ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["capabilities"] = json.loads(d["capabilities"])
        d["metrics"] = json.loads(d["metrics"]) if d.get("metrics") else {}
        return d

    # -- retention ---------------------------------------------------------

    def apply_retention(
        self,
        *,
        raw_hours: int,
        medium_days: int,
        high_days: int,
        case_days: int,
    ) -> dict[str, int]:
        """Delete events past their retention window by risk band (spec 23.3)."""
        now = datetime.now(timezone.utc)
        cutoffs = {
            "low": now - timedelta(hours=raw_hours),
            "medium": now - timedelta(days=medium_days),
            "high": now - timedelta(days=high_days),
        }
        deleted: dict[str, int] = {}
        with self._lock:
            case_linked = {
                r["event_id"]
                for r in self._conn.execute("SELECT event_id FROM case_events").fetchall()
            }
            for band, cutoff in cutoffs.items():
                cutoff_iso = cutoff.isoformat().replace("+00:00", "Z")
                # Never delete case-linked events before case retention.
                rows = self._conn.execute(
                    "SELECT event_id FROM events WHERE risk_band=? AND received_at < ?",
                    (band, cutoff_iso),
                ).fetchall()
                to_delete = [r["event_id"] for r in rows if r["event_id"] not in case_linked]
                self._conn.executemany(
                    "DELETE FROM events WHERE event_id = ?", [(i,) for i in to_delete]
                )
                deleted[band] = len(to_delete)
        return deleted

    def integrity_check(self) -> bool:
        with self._lock:
            row = self._conn.execute("PRAGMA integrity_check").fetchone()
        return bool(row) and row[0] == "ok"

    def db_size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0
