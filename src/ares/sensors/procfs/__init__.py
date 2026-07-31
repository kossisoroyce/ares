"""procfs/psutil-based fallback sensors (spec 8.2)."""

from ares.sensors.procfs.network import NetworkSensor
from ares.sensors.procfs.process import ProcessSensor

__all__ = ["ProcessSensor", "NetworkSensor"]
