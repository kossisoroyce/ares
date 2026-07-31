"""Host and boot identity detection (spec 7.1, 25.2)."""

from __future__ import annotations

import hashlib
import platform
import socket
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HostIdentity:
    host_id: str
    boot_id: str
    hostname: str
    platform: str


def _stable_host_id() -> str:
    """Derive a stable host id.

    Prefers /etc/machine-id (Linux), then a hash of the MAC + hostname so the
    same host keeps the same id across reboots.
    """
    machine_id_path = Path("/etc/machine-id")
    if machine_id_path.exists():
        raw = machine_id_path.read_text().strip()
        if raw:
            return "host_" + hashlib.sha256(raw.encode()).hexdigest()[:20]
    seed = f"{uuid.getnode()}:{socket.gethostname()}"
    return "host_" + hashlib.sha256(seed.encode()).hexdigest()[:20]


def _boot_id() -> str:
    """Per-boot identifier (spec 25.2: new boot_id on reboot)."""
    proc_boot = Path("/proc/sys/kernel/random/boot_id")
    if proc_boot.exists():
        raw = proc_boot.read_text().strip().replace("-", "")
        if raw:
            return "boot_" + raw[:16]
    # Non-Linux/dev fallback: derive from boot time when available.
    try:
        import psutil  # type: ignore

        return "boot_" + hashlib.sha256(str(psutil.boot_time()).encode()).hexdigest()[:16]
    except Exception:
        return "boot_" + uuid.uuid4().hex[:16]


def detect_host_identity() -> HostIdentity:
    return HostIdentity(
        host_id=_stable_host_id(),
        boot_id=_boot_id(),
        hostname=socket.gethostname(),
        platform=platform.system(),
    )
