"""Enrichment pipeline with lazy/budgeted expensive fields (spec 10).

Enrichers add derived context to events. Cheap enrichers (host role,
environment) run inline for every event; expensive ones (file hashes, reverse
DNS, threat-intel) are marked ``lazy`` and only run for elevated-severity
events so the daemon does not pay their cost on every event.
"""

from __future__ import annotations

import abc

from ares.config import Config
from ares.events import Event


class Enricher(abc.ABC):
    name = "enricher"
    lazy = False  # lazy enrichers only run when explicitly requested (spec 10)

    @abc.abstractmethod
    def enrich(self, event: Event) -> dict:  # pragma: no cover - interface
        ...


class HostContextEnricher(Enricher):
    name = "host_context"

    def __init__(self, role: str, environment: str, criticality: str) -> None:
        self._ctx = {
            "host_role": role,
            "environment": environment,
            "asset_criticality": criticality,
        }

    def enrich(self, event: Event) -> dict:
        return dict(self._ctx)


class ExecutableHashEnricher(Enricher):
    """Lazy: hash the executable of a process exec event (spec 10)."""

    name = "executable_hash"
    lazy = True

    def enrich(self, event: Event) -> dict:
        import hashlib
        from pathlib import Path

        exe = event.get("executable")
        if not exe:
            return {}
        p = Path(exe)
        if not p.is_file():
            return {}
        try:
            h = hashlib.sha256()
            with p.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return {"executable_hash": h.hexdigest()}
        except OSError:
            return {}


class EnrichmentPipeline:
    def __init__(self, config: Config, lazy_threshold: float = 0.3) -> None:
        self._lazy_threshold = lazy_threshold
        self._enrichers: list[Enricher] = [
            HostContextEnricher(config.host.role, config.host.environment, config.host.criticality),
            ExecutableHashEnricher(),
        ]

    def register(self, enricher: Enricher) -> None:
        self._enrichers.append(enricher)

    def enrich(self, event: Event) -> Event:
        run_lazy = event.severity_hint >= self._lazy_threshold
        for enricher in self._enrichers:
            if enricher.lazy and not run_lazy:
                continue
            try:
                event.enrichment.update(enricher.enrich(event))
            except Exception:  # enrichment must never drop an event
                continue
        return event
