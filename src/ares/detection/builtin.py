"""Initial high-value streaming rules (spec 12.2).

These cover the single-event and cheap-lookup detections. Multi-step sequence
detections (file written -> executed -> connected -> deleted, spec 12.2 #20)
are scored by the correlation engine (spec 16), which has the cross-event view.
"""

from __future__ import annotations

import base64
import re

from ares.detection.rule import Finding, Rule, RuleContext
from ares.events import Event, EventType

_SHELLS = {"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/usr/bin/sh", "/usr/bin/bash"}
_WRITABLE_EXEC_DIRS = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/shm/",
    # macOS resolves /tmp and /var/tmp through /private (dev environments).
    "/private/tmp/",
    "/private/var/tmp/",
)


class NetworkServiceSpawnedShell(Rule):
    """#1: Network service spawning a shell — classic reverse-shell primitive."""

    rule_id = "PROC_NET_SHELL_001"
    title = "Network service spawned a shell"
    severity = "high"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if event.type != EventType.PROCESS_EXEC.value:
            return None
        exe = event.get("executable") or ""
        name = event.get("name") or ""
        if exe not in _SHELLS and name not in {"sh", "bash", "dash", "zsh"}:
            return None
        if not event.get("parent_is_network_service"):
            return None
        return self._finding(
            event,
            risk_score=0.88,
            confidence=0.9,
            immediate=True,
            reasons=[
                f"Shell {exe or name} spawned",
                f"Parent process is a network service ({event.get('parent_name')})",
            ],
        )


class TempExecution(Rule):
    """#2: Execution from /tmp, /dev/shm, or other writable directories."""

    rule_id = "PROC_TEMP_EXEC_002"
    title = "Executable launched from a writable/temporary directory"
    severity = "high"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if event.type != EventType.PROCESS_EXEC.value:
            return None
        exe = event.get("executable") or ""
        if not exe.startswith(_WRITABLE_EXEC_DIRS):
            return None
        reasons = [f"Executable launched from {exe}"]
        immediate = bool(event.get("parent_is_network_service"))
        if immediate:
            reasons.append(f"Parent is network service ({event.get('parent_name')})")
        return self._finding(
            event,
            risk_score=0.82 if immediate else 0.7,
            confidence=0.85,
            immediate=immediate,
            reasons=reasons,
        )


class FirstSeenExternalDestination(Rule):
    """#5: New process contacting a first-seen external destination."""

    rule_id = "NET_FIRST_SEEN_005"
    title = "Connection to a first-seen external destination"
    severity = "medium"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if event.type != EventType.NETWORK_CONNECT.value:
            return None
        if not event.get("is_external"):
            return None
        dest = event.get("destination")
        if not dest:
            return None
        first_seen = context.store.observe_destination(event.host_id, dest)
        if not first_seen:
            return None
        return self._finding(
            event,
            risk_score=0.55,
            confidence=0.7,
            reasons=[f"First connection to external destination {dest}"],
        )


class AuthorizedKeysModified(Rule):
    """#6: Changes to authorized_keys."""

    rule_id = "PERSIST_SSH_KEYS_006"
    title = "SSH authorized_keys modified"
    severity = "high"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if not event.type.startswith("file."):
            return None
        path = event.get("path") or ""
        if "authorized_keys" not in path:
            return None
        return self._finding(
            event,
            risk_score=0.8,
            confidence=0.85,
            immediate=True,
            reasons=[f"authorized_keys modified: {path}"],
        )


class CronOrTimerCreated(Rule):
    """#7: New cron job or systemd timer."""

    rule_id = "PERSIST_CRON_TIMER_007"
    title = "New scheduled task (cron/systemd timer) created or modified"
    severity = "high"

    _MATCH = ("/etc/cron", "/var/spool/cron", "/etc/systemd")

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if event.type not in {EventType.FILE_CREATE.value, EventType.FILE_MODIFY.value}:
            return None
        path = event.get("path") or ""
        if not path.startswith(self._MATCH):
            return None
        is_timer = path.endswith(".timer") or "cron" in path
        if not is_timer and not path.startswith(self._MATCH):
            return None
        return self._finding(
            event,
            risk_score=0.68,
            confidence=0.75,
            reasons=[f"Persistence path changed: {path}"],
        )


class SudoersModified(Rule):
    """#10: Modification of /etc/sudoers."""

    rule_id = "PRIV_SUDOERS_010"
    title = "/etc/sudoers modified"
    severity = "critical"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if not event.type.startswith("file."):
            return None
        path = event.get("path") or ""
        if not (path == "/etc/sudoers" or path.startswith("/etc/sudoers.d")):
            return None
        return self._finding(
            event,
            risk_score=0.9,
            confidence=0.9,
            immediate=True,
            reasons=[f"sudoers configuration changed: {path}"],
        )


class NewPrivilegedUser(Rule):
    """#8: Creation of a new (potentially privileged) user."""

    rule_id = "IDENT_NEW_USER_008"
    title = "New user account created"
    severity = "high"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if event.type != EventType.IDENTITY_USER_CREATED.value:
            return None
        user = event.get("user")
        return self._finding(
            event,
            risk_score=0.72,
            confidence=0.8,
            immediate=user == "root",
            reasons=[f"User created: {user}"],
        )


class EncodedCommandArguments(Rule):
    """#12: Encoded or heavily obfuscated command arguments.

    Tuned for precision: long base64-looking tokens are extremely common in
    benign command lines (paths, digests, cache keys), so a bare base64 blob is
    not enough. This rule fires only when either

      * an explicit "encoded command" flag is present (e.g. ``powershell -enc``,
        ``base64 -d``), or
      * the process is a script interpreter *and* a long base64 argument decodes
        to text that itself looks like code (imports, shell, exec, sockets).
    """

    rule_id = "PROC_ENCODED_ARGS_012"
    title = "Encoded or obfuscated command arguments"
    severity = "medium"

    _INTERPRETERS = {
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
        "sh",
        "bash",
        "dash",
        "zsh",
        "powershell",
        "pwsh",
    }
    _ENC_FLAGS = {"-enc", "-encodedcommand", "-e", "-ec"}
    _LONG_B64 = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")
    _SUSPICIOUS_DECODED = re.compile(
        r"(?i)(import\s+os|import\s+socket|subprocess|/bin/|exec\(|eval\(|base64|"
        r"socket\.|powershell|Invoke-|curl\s|wget\s|/dev/tcp)"
    )

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if event.type != EventType.PROCESS_EXEC.value:
            return None
        argv = [a for a in (event.get("argv") or []) if isinstance(a, str)]
        if not argv:
            return None

        name = (event.get("name") or "").lower()
        exe = (event.get("executable") or "").lower()
        is_interpreter = name in self._INTERPRETERS or any(
            exe.endswith(i) for i in self._INTERPRETERS
        )

        # Explicit encoded-command flag (e.g. base64 -d, powershell -enc).
        lowered = {a.lower() for a in argv}
        if lowered & self._ENC_FLAGS and (is_interpreter or "base64" in name):
            return self._finding(
                event,
                risk_score=0.7,
                confidence=0.8,
                reasons=["Explicit encoded-command flag present"],
            )

        # Interpreter + base64 blob that decodes to code-like content.
        if is_interpreter:
            for arg in argv:
                if self._LONG_B64.match(arg):
                    decoded = self._decode(arg)
                    if decoded and self._SUSPICIOUS_DECODED.search(decoded):
                        return self._finding(
                            event,
                            risk_score=0.75,
                            confidence=0.8,
                            reasons=["Base64 argument decodes to code-like content"],
                        )
        return None

    @staticmethod
    def _decode(s: str) -> str | None:
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None


class NewListeningPort(Rule):
    """#14: Process listening on a new port."""

    rule_id = "NET_NEW_LISTEN_014"
    title = "Process began listening on a new port"
    severity = "medium"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if event.type != EventType.NETWORK_ACCEPT.value:
            return None
        port = event.get("listening_port")
        if port is None:
            return None
        first = context.store.observe_destination(event.host_id, f"listen:{port}")
        if not first:
            return None
        return self._finding(
            event,
            risk_score=0.5,
            confidence=0.6,
            reasons=[f"New listening port {port}"],
        )


class UnexpectedUidTransition(Rule):
    """#9: Unexpected UID transition (non-root parent, root child)."""

    rule_id = "PRIV_UID_TRANSITION_009"
    title = "Unexpected privilege transition"
    severity = "high"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if event.type != EventType.PROCESS_EXEC.value:
            return None
        uid = event.get("uid")
        parent = context.parent_process(event)
        if uid != 0 or not parent:
            return None
        parent_uid = parent.get("uid")
        if parent_uid in (None, 0):
            return None
        return self._finding(
            event,
            risk_score=0.75,
            confidence=0.7,
            reasons=[f"Process runs as root but parent ran as uid {parent_uid}"],
        )


class FailedLoginBurst(Rule):
    """#19: Rapid failed-login burst followed by success (stateful)."""

    rule_id = "IDENT_BRUTE_FORCE_019"
    title = "Failed-login burst"
    severity = "high"

    def __init__(self, threshold: int = 5, window_seconds: float = 60.0) -> None:
        self._threshold = threshold
        self._window = window_seconds
        self._failures: dict[str, list[float]] = {}

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        import time

        if event.type == EventType.IDENTITY_LOGIN_FAILED.value:
            src = event.get("source") or "unknown"
            now = time.time()
            bucket = [t for t in self._failures.get(src, []) if now - t < self._window]
            bucket.append(now)
            self._failures[src] = bucket
            if len(bucket) >= self._threshold:
                return self._finding(
                    event,
                    risk_score=0.7,
                    confidence=0.8,
                    reasons=[f"{len(bucket)} failed logins from {src} within {int(self._window)}s"],
                )
        elif event.type == EventType.IDENTITY_LOGIN.value:
            src = event.get("source") or "unknown"
            bucket = self._failures.get(src, [])
            if len(bucket) >= self._threshold:
                self._failures[src] = []
                return self._finding(
                    event,
                    risk_score=0.85,
                    confidence=0.85,
                    immediate=True,
                    reasons=[
                        f"Successful login from {src} after {len(bucket)} failures (possible brute force)"
                    ],
                )
        return None


#: Default rule set instantiated by the engine.
BUILTIN_RULES: list[Rule] = [
    NetworkServiceSpawnedShell(),
    TempExecution(),
    FirstSeenExternalDestination(),
    AuthorizedKeysModified(),
    CronOrTimerCreated(),
    SudoersModified(),
    NewPrivilegedUser(),
    EncodedCommandArguments(),
    NewListeningPort(),
    UnexpectedUidTransition(),
    FailedLoginBurst(),
]
