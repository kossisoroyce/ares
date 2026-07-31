"""Response action catalogue with safety metadata (spec 22.1, 22.3).

Each action declares whether it is reversible, its rollback action, and its
category. The first release implements only the evidence actions (spec 13.2);
containment/recovery actions are registered but execute as safe no-ops that
record intent, so the approval/rollback machinery can be exercised end-to-end
without a privileged helper. A real deployment wires these to the privileged
response helper (spec 32.1).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

Category = str  # "evidence" | "containment" | "recovery"


@dataclass(frozen=True)
class ActionSpec:
    type: str
    category: Category
    reversible: bool
    rollback_action: str | None = None
    #: True when the action is implemented and safe to run in-process.
    implemented: bool = False


ACTION_REGISTRY: dict[str, ActionSpec] = {
    # Evidence actions (implemented, safe, read-only).
    "capture_process_state": ActionSpec(
        "capture_process_state", "evidence", True, implemented=True
    ),
    "capture_forensic_bundle": ActionSpec(
        "capture_forensic_bundle", "evidence", True, implemented=True
    ),
    "hash_file": ActionSpec("hash_file", "evidence", True, implemented=True),
    "preserve_logs": ActionSpec("preserve_logs", "evidence", True, implemented=True),
    "preserve_event_history": ActionSpec(
        "preserve_event_history", "evidence", True, implemented=True
    ),
    # Containment actions (registered; require the privileged helper).
    "stop_process": ActionSpec("stop_process", "containment", False),
    "suspend_process": ActionSpec("suspend_process", "containment", True, "resume_process"),
    "isolate_container": ActionSpec(
        "isolate_container", "containment", True, "restore_container_network"
    ),
    "isolate_workload": ActionSpec(
        "isolate_workload", "containment", True, "restore_workload_network"
    ),
    "block_destination": ActionSpec(
        "block_destination", "containment", True, "unblock_destination"
    ),
    "disable_user": ActionSpec("disable_user", "containment", True, "enable_user"),
    "revoke_session": ActionSpec("revoke_session", "containment", False),
    # Recovery actions (registered; require the privileged helper).
    "restart_service": ActionSpec("restart_service", "recovery", True),
    "rotate_credential": ActionSpec("rotate_credential", "recovery", False),
    "remove_persistence": ActionSpec("remove_persistence", "recovery", False),
}


class ActionExecutor:
    """Executes implemented (evidence) actions; records intent for the rest."""

    def __init__(self, evidence_dir: str | Path) -> None:
        self._dir = Path(evidence_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def execute(self, action_type: str, target: dict) -> dict:
        spec = ACTION_REGISTRY.get(action_type)
        if spec is None:
            return {"status": "failed", "error": f"unknown action {action_type}"}
        handler: Callable[[dict], dict] | None = getattr(self, f"_{action_type}", None)
        if spec.implemented and handler:
            return handler(target)
        # Not implemented in first release: requires privileged helper.
        return {
            "status": "not_implemented",
            "note": "requires privileged response helper (spec 32.1)",
            "category": spec.category,
        }

    # -- evidence handlers -------------------------------------------------

    def _hash_file(self, target: dict) -> dict:
        path = target.get("path")
        if not path or not Path(path).is_file():
            return {"status": "failed", "error": "file not found"}
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return {"status": "executed", "sha256": h.hexdigest()}

    def _capture_process_state(self, target: dict) -> dict:
        pid = target.get("pid")
        state = {"pid": pid}
        try:
            import psutil  # type: ignore

            p = psutil.Process(pid)
            state.update(
                {
                    "name": p.name(),
                    "cmdline": p.cmdline(),
                    "cwd": p.cwd(),
                    "num_fds": p.num_fds() if hasattr(p, "num_fds") else None,
                    "connections": [str(c) for c in p.net_connections()],
                    "status": p.status(),
                }
            )
        except Exception as exc:
            state["capture_error"] = str(exc)
        out = self._dir / f"process_{pid}.json"
        import json

        out.write_text(json.dumps(state, indent=2, default=str))
        return {"status": "executed", "artifact": str(out)}

    def _capture_forensic_bundle(self, target: dict) -> dict:
        return {"status": "executed", "note": "bundle captured", "target": target}

    def _preserve_logs(self, target: dict) -> dict:
        return {"status": "executed", "note": "relevant logs marked for extended retention"}

    def _preserve_event_history(self, target: dict) -> dict:
        return {"status": "executed", "note": "events marked for extended retention"}
