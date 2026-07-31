"""Detect and remove secrets from telemetry before storage/model use (spec 11.2).

The redactor is deliberately conservative: it operates on strings and argv
lists and returns the list of fields it touched so the event's ``redaction``
block stays auditable. It never sends raw values anywhere; it only rewrites
them in place to ``[REDACTED]``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"

# Flags whose *following* token is a secret, e.g. ``--password secret``.
_SECRET_FLAGS = {
    "--password",
    "-p",
    "--passwd",
    "--pass",
    "--token",
    "--api-key",
    "--apikey",
    "--secret",
    "--secret-key",
    "--access-key",
    "--auth",
    "--bearer",
    "--private-key",
}

# Inline ``key=value`` secret assignments.
_KV_SECRET = re.compile(
    r"(?i)\b([a-z0-9_.\-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|auth|bearer|session[_-]?id|cookie)[a-z0-9_.\-]*)"
    r"\s*[=:]\s*(\"[^\"]*\"|'[^']*'|\S+)"
)

# High-signal value patterns that indicate a secret regardless of key name.
_VALUE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),  # AWS temp access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),  # GitHub tokens
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),  # Slack tokens
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),  # OpenAI-style keys
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b"),  # JWT
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    ),  # PEM private key header
    # Connection strings such as postgres://user:pass@host/db
    re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^:/\s]+:([^@/\s]+)@"),
]


class Redactor:
    def __init__(self, extra_flags: Iterable[str] | None = None) -> None:
        self._flags = set(_SECRET_FLAGS)
        if extra_flags:
            self._flags.update(extra_flags)

    # -- argv --------------------------------------------------------------

    def redact_argv(self, argv: list[str]) -> tuple[list[str], list[str]]:
        """Redact a command-line argument vector.

        Returns ``(redacted_argv, fields_removed)``.
        """
        out: list[str] = []
        removed: list[str] = []
        expect_secret = False
        for i, arg in enumerate(argv):
            if expect_secret:
                out.append(REDACTED)
                removed.append(f"argv[{i}]")
                expect_secret = False
                continue

            flag, sep, val = arg.partition("=")
            if flag.lower() in self._flags and sep == "=":
                out.append(f"{flag}={REDACTED}")
                removed.append(f"argv[{i}]")
                continue
            if arg.lower() in self._flags:
                out.append(arg)
                expect_secret = True
                continue

            redacted, hit = self._redact_text(arg)
            out.append(redacted)
            if hit:
                removed.append(f"argv[{i}]")
        return out, removed

    # -- free text ---------------------------------------------------------

    def redact_text(self, text: str) -> str:
        return self._redact_text(text)[0]

    def _redact_text(self, text: str) -> tuple[str, bool]:
        original = text

        def _kv_sub(m: re.Match[str]) -> str:
            return f"{m.group(1)}={REDACTED}"

        text = _KV_SECRET.sub(_kv_sub, text)
        for pat in _VALUE_PATTERNS:
            if pat.groups:
                # Redact only the captured secret group, keep surrounding context.
                text = pat.sub(lambda m: m.group(0).replace(m.group(1), REDACTED), text)
            else:
                text = pat.sub(REDACTED, text)
        return text, text != original

    # -- env var names -----------------------------------------------------

    def env_names_only(self, env: dict[str, str]) -> list[str]:
        """Return only environment variable *names* (spec 14.3, values excluded)."""
        return sorted(env.keys())
