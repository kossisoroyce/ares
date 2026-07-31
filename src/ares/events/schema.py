"""Shared event envelope and typed payloads (spec section 9)."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from ares.events.ids import new_event_id, now_ns

SCHEMA_VERSION = "1.0"


class EventType(str, enum.Enum):
    """Required event categories (spec 9.1)."""

    PROCESS_EXEC = "process.exec"
    PROCESS_EXIT = "process.exit"
    NETWORK_CONNECT = "network.connect"
    NETWORK_ACCEPT = "network.accept"
    FILE_CREATE = "file.create"
    FILE_MODIFY = "file.modify"
    FILE_DELETE = "file.delete"
    FILE_RENAME = "file.rename"
    FILE_PERMISSION_CHANGE = "file.permission_change"
    IDENTITY_LOGIN = "identity.login"
    IDENTITY_LOGIN_FAILED = "identity.login_failed"
    IDENTITY_USER_CREATED = "identity.user_created"
    IDENTITY_GROUP_CHANGED = "identity.group_changed"
    PRIVILEGE_CHANGE = "privilege.change"
    PERSISTENCE_CREATED = "persistence.created"
    PERSISTENCE_MODIFIED = "persistence.modified"
    PACKAGE_INSTALLED = "package.installed"
    PACKAGE_REMOVED = "package.removed"
    SERVICE_CREATED = "service.created"
    SERVICE_MODIFIED = "service.modified"
    CONTAINER_STARTED = "container.started"
    CONTAINER_STOPPED = "container.stopped"
    DEPLOYMENT_STARTED = "deployment.started"
    DEPLOYMENT_COMPLETED = "deployment.completed"


EVENT_TYPES = tuple(t.value for t in EventType)


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Redaction(BaseModel):
    fields_removed: list[str] = Field(default_factory=list)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Event(BaseModel):
    """Shared envelope for all collected events (spec 9).

    ``payload`` holds event-type specific fields; ``enrichment`` holds derived
    context added by the userspace daemon (spec 10). Keeping these as open dicts
    lets sensors evolve without a schema migration on every new field, while the
    envelope stays stable and queryable.
    """

    schema_version: str = SCHEMA_VERSION
    event_id: str = Field(default_factory=new_event_id)
    host_id: str
    boot_id: str
    timestamp_ns: int = Field(default_factory=now_ns)
    received_at: str = Field(default_factory=_utcnow_iso)
    event_type: EventType
    source: str = "unknown"  # ebpf | audit | procfs | filesystem | ...
    severity_hint: float = 0.0
    process_id: str | None = None
    user_id: str | None = None
    container_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    redaction: Redaction = Field(default_factory=Redaction)

    model_config = {"use_enum_values": True}

    # Convenience accessors used throughout the pipeline ------------------

    @property
    def type(self) -> str:
        return self.event_type if isinstance(self.event_type, str) else self.event_type.value

    def get(self, key: str, default: Any = None) -> Any:
        """Look up a value from payload first, then enrichment."""
        if key in self.payload:
            return self.payload[key]
        return self.enrichment.get(key, default)
