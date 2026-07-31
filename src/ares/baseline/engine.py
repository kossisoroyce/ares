"""Learn normal behaviour per host/workload/executable (spec 17).

The engine records observations across several dimensions (spec 17.1) and can
answer "is this new/rare for this host?" It excludes high-risk findings from
baseline updates and can freeze during active incidents to resist baseline
poisoning (spec 17.4).
"""

from __future__ import annotations

from datetime import datetime, timezone

from ares.events import Event, EventType
from ares.storage import Store


class BaselineEngine:
    def __init__(self, store: Store, learning_period_days: int = 7) -> None:
        self._store = store
        self._learning_period_days = learning_period_days
        self._frozen = False

    def freeze(self, frozen: bool = True) -> None:
        """Freeze baseline acceptance during an active incident (spec 17.4)."""
        self._frozen = frozen
        self._store.freeze_baselines(frozen)

    def observe(self, event: Event, high_risk: bool = False) -> None:
        """Fold an event into the baseline unless it is high-risk or frozen."""
        if self._frozen or high_risk:
            return  # exclude high-risk findings from baseline (spec 17.4)
        for dimension, key in self._dimensions(event):
            self._store.observe_baseline(dimension, key)

    def deviation(self, event: Event) -> float:
        """Return a 0..1 novelty score: how unusual this event is for the host.

        1.0 means never-before-seen on every tracked dimension; 0.0 means all
        dimensions are well-established.
        """
        dims = self._dimensions(event)
        if not dims:
            return 0.0
        novelty = 0.0
        for dimension, key in dims:
            count = self._store.baseline_count(dimension, key)
            # Diminishing novelty as observations accumulate.
            novelty += 1.0 / (1.0 + count)
        return round(min(novelty / len(dims), 1.0), 3)

    def is_new(self, event: Event) -> bool:
        return all(self._store.baseline_count(d, k) == 0 for d, k in self._dimensions(event))

    def _dimensions(self, event: Event) -> list[tuple[str, str]]:
        """Map an event to its baseline dimension keys (spec 17.1)."""
        host = event.host_id
        dims: list[tuple[str, str]] = []
        if event.type == EventType.PROCESS_EXEC.value:
            exe = event.get("executable") or ""
            parent = event.get("parent_name") or event.get("parent_executable") or ""
            dims.append(("host:executable", f"{host}|{exe}"))
            if parent:
                dims.append(("executable:parent", f"{exe}|{parent}"))
            hour = datetime.now(timezone.utc).hour
            dims.append(("host:executable:hour", f"{host}|{exe}|{hour}"))
        elif event.type == EventType.NETWORK_CONNECT.value:
            dest = event.get("destination") or ""
            dims.append(("host:destination", f"{host}|{dest}"))
        elif event.type == EventType.NETWORK_ACCEPT.value:
            port = event.get("listening_port")
            dims.append(("host:listen_port", f"{host}|{port}"))
        elif event.type.startswith("file."):
            path = event.get("path") or ""
            dims.append(("host:file_write", f"{host}|{path}"))
        return dims

    def status(self) -> dict:
        summary = self._store.baseline_summary()
        return {
            "frozen": self._frozen,
            "learning_period_days": self._learning_period_days,
            "dimensions": summary,
            "total_keys": sum(summary.values()),
        }
