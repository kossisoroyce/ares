"""Assemble the active sensor set from config and platform (spec 8)."""

from __future__ import annotations

import platform

from ares.config import Config
from ares.redaction import Redactor
from ares.sensors.base import EventCallback, Sensor
from ares.sensors.filesystem import FilesystemSensor
from ares.sensors.host import HostIdentity
from ares.sensors.procfs import NetworkSensor, ProcessSensor


def build_sensors(
    config: Config, host: HostIdentity, emit: EventCallback, redactor: Redactor | None = None
) -> list[Sensor]:
    """Return the list of sensors to run given config and environment.

    On Linux the eBPF sensors would be preferred here; this first release ships
    the psutil/procfs fallback collectors which run everywhere. Unavailable
    sensors are filtered out and surfaced via capability reporting.
    """
    redactor = redactor or Redactor()
    sensors: list[Sensor] = []

    if config.sensors.process.enabled:
        sensors.append(
            ProcessSensor(
                emit,
                host,
                redactor,
                include_arguments=config.privacy.include_command_arguments,
            )
        )
    if config.sensors.network.enabled:
        sensors.append(NetworkSensor(emit, host))
    if config.sensors.filesystem.enabled:
        sensors.append(
            FilesystemSensor(
                emit,
                host,
                protected_paths=config.sensors.filesystem.protected_paths,
                ignored_paths=config.sensors.filesystem.ignored_paths,
            )
        )
    # identity/container sensors are Linux-specific (auth logs, cgroups) and are
    # omitted from the cross-platform fallback set. They attach on Linux.
    if config.sensors.identity.enabled and platform.system() == "Linux":
        try:
            from ares.sensors.audit import IdentitySensor  # noqa: WPS433

            sensors.append(IdentitySensor(emit, host))
        except Exception:
            pass

    return [s for s in sensors if s.available()]
