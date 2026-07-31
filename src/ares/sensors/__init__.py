"""Sensor layer (spec section 8).

The daemon loads a set of :class:`Sensor` implementations. On Linux the
preferred sensors are eBPF-based; when eBPF is unavailable the daemon falls
back to procfs/psutil/inotify equivalents (spec 8.2). Each sensor reports its
capabilities so the interface can surface missing coverage (spec 8.3).
"""

from ares.sensors.base import Sensor, SensorCapabilities
from ares.sensors.host import HostIdentity, detect_host_identity
from ares.sensors.registry import build_sensors

__all__ = [
    "Sensor",
    "SensorCapabilities",
    "HostIdentity",
    "detect_host_identity",
    "build_sensors",
]
