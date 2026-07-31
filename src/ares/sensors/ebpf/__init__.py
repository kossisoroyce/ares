"""eBPF sensor loader (spec 8.1) — Linux only.

The compiled BPF programs live under ``bpf/`` at the repo root. This package is
the userspace loader that attaches them (via a library such as libbpf/BCC/
bpftrace) and reads events from the BPF ring buffer.

The first release ships the BPF C sources and the procfs fallback collectors;
wiring the loader is an integration step performed on a Linux host with the
kernel headers present. Importing this module on a non-Linux host is a no-op.
"""

from __future__ import annotations

import platform


def ebpf_supported() -> bool:
    """Report whether eBPF program loading is possible on this host."""
    if platform.system() != "Linux":
        return False
    try:
        import ctypes  # noqa: F401

        return True  # a real check probes CAP_BPF / kernel version / BTF
    except Exception:  # pragma: no cover
        return False


__all__ = ["ebpf_supported"]
