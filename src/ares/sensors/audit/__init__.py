"""Linux Audit / journald fallback sensors (spec 8.2).

Only active on Linux. Parses auth logs / journald for identity events
(logins, sudo, user creation). Kept minimal in the first release.
"""

from ares.sensors.audit.identity import IdentitySensor

__all__ = ["IdentitySensor"]
