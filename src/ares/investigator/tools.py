"""Safe, read-only, typed investigator tools (spec 19.3).

The agent never generates shell commands. It may only call these typed tools,
each of which is read-only and host-scoped. Every call is recorded so the
investigation has a full audit log (spec 19.2).
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ares.storage import Store


@dataclass
class ToolResult:
    ok: bool
    data: Any = None
    error: str | None = None


@dataclass
class InvestigatorTools:
    """Read-only tool surface bound to a single host/case.

    ``call_count`` is enforced against the per-case tool-call budget by the
    investigator (spec 19.2). Tools that would touch the filesystem are limited
    to metadata/hashing and never read file *contents* into the model unless
    policy explicitly allows it (spec 11.1).
    """

    store: Store
    host_id: str
    allow_file_contents: bool = False
    call_count: int = 0
    audit_log: list[dict] = field(default_factory=list)

    def _record(self, name: str, args: dict, result: ToolResult) -> ToolResult:
        self.call_count += 1
        self.audit_log.append({"tool": name, "args": args, "ok": result.ok, "error": result.error})
        return result

    # -- schema for AI providers ------------------------------------------

    def schemas(self) -> list[dict]:
        """JSON-schema tool definitions for AI providers (typed inputs)."""
        return [
            {
                "name": "get_process_ancestry",
                "description": "Return the ancestry chain for a process id.",
                "input_schema": {
                    "type": "object",
                    "properties": {"process_id": {"type": "string"}},
                    "required": ["process_id"],
                },
            },
            {
                "name": "get_related_events",
                "description": "Return recent events for a process id.",
                "input_schema": {
                    "type": "object",
                    "properties": {"process_id": {"type": "string"}, "limit": {"type": "integer"}},
                    "required": ["process_id"],
                },
            },
            {
                "name": "get_file_metadata",
                "description": "Return metadata (size, perms, owner) for a path. No contents.",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
            {
                "name": "hash_file",
                "description": "Return the SHA-256 of a file at a path.",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
            {
                "name": "check_destination_reputation",
                "description": "Return how often a destination has been seen on this host.",
                "input_schema": {
                    "type": "object",
                    "properties": {"destination": {"type": "string"}},
                    "required": ["destination"],
                },
            },
            {
                "name": "search_prior_cases",
                "description": "Search previously investigated cases on this host.",
                "input_schema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            },
        ]

    def dispatch(self, name: str, args: dict) -> ToolResult:
        fn: Callable[..., ToolResult] | None = getattr(self, name, None)
        if fn is None or name not in {s["name"] for s in self.schemas()}:
            # Record rejected attempts too — an agent probing for tools it does
            # not have is itself security-relevant (spec 19.2 full audit log).
            return self._record(name, args, ToolResult(ok=False, error=f"unknown tool: {name}"))
        try:
            return self._record(name, args, fn(**args))
        except TypeError as exc:
            return self._record(name, args, ToolResult(ok=False, error=str(exc)))

    # -- tool implementations ---------------------------------------------

    def get_process_ancestry(self, process_id: str) -> ToolResult:
        chain = self.store.process_ancestry(process_id)
        return ToolResult(ok=True, data=chain)

    def get_related_events(self, process_id: str, limit: int = 50) -> ToolResult:
        events = self.store.search_events(process=process_id, limit=limit)
        return ToolResult(ok=True, data=[e.model_dump() for e in events])

    def get_file_metadata(self, path: str) -> ToolResult:
        try:
            st = os.stat(path)
        except OSError as exc:
            return ToolResult(ok=False, error=str(exc))
        return ToolResult(
            ok=True,
            data={
                "path": path,
                "size": st.st_size,
                "permissions": oct(st.st_mode & 0o777),
                "owner_uid": st.st_uid,
                "modified": st.st_mtime,
                "is_executable": bool(st.st_mode & 0o111),
            },
        )

    def hash_file(self, path: str) -> ToolResult:
        p = Path(path)
        if not p.is_file():
            return ToolResult(ok=False, error="not a file")
        h = hashlib.sha256()
        try:
            with p.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
        except OSError as exc:
            return ToolResult(ok=False, error=str(exc))
        return ToolResult(ok=True, data={"sha256": h.hexdigest(), "path": path})

    def check_destination_reputation(self, destination: str) -> ToolResult:
        # First-seen tracking already lives in the store; expose the count.
        with self.store._lock:  # noqa: SLF001 - internal read
            row = self.store._conn.execute(
                "SELECT seen_count, first_seen, last_seen FROM network_destinations "
                "WHERE host_id=? AND destination=?",
                (self.host_id, destination),
            ).fetchone()
        if not row:
            return ToolResult(ok=True, data={"destination": destination, "seen_count": 0})
        return ToolResult(ok=True, data=dict(row))

    def search_prior_cases(self, query: str) -> ToolResult:
        cases = [
            c
            for c in self.store.list_cases()
            if query.lower() in (c.get("summary") or "").lower()
            or query.lower() in (c.get("title") or "").lower()
        ]
        return ToolResult(ok=True, data=cases[:10])
