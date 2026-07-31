"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from ares.config import Config
from ares.storage import Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "test.db")
    yield s
    s.close()


@pytest.fixture
def config(tmp_path):
    return Config.model_validate(
        {
            "host": {"role": "test", "environment": "test", "criticality": "high"},
            "storage": {"path": str(tmp_path / "test.db")},
            "investigation": {"model_provider": "local", "model": "template"},
        }
    )
