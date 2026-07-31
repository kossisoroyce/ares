"""Project Ares — AI-native host security investigator.

Public entry point::

    from ares import Ares
    client = Ares.from_config("/etc/ares/config.yaml")
    status = client.status()
    findings = client.findings.list(severity="high")
    cases = client.cases.list(status="open")
"""

from ares.client import Ares

__all__ = ["Ares", "__version__"]

__version__ = "0.1.0"
