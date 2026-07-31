"""Notifier plugin interface and message model (spec 28.3)."""

from __future__ import annotations

import abc
from dataclasses import dataclass


@dataclass
class Notification:
    title: str
    body: str
    severity: str = "medium"
    case_id: str | None = None
    url: str | None = None


class Notifier(abc.ABC):
    name = "notifier"

    @abc.abstractmethod
    def send(self, message: Notification) -> None:  # pragma: no cover - interface
        ...
