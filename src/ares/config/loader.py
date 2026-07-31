"""Load and validate configuration from YAML (spec 27), with a dev fallback."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from ares.config.models import Config

DEFAULT_CONFIG_PATH = "/etc/ares/config.yaml"


def _dev_defaults() -> dict:
    """Sensible defaults for running on a developer machine (e.g. macOS).

    Uses a state directory under the user's home so no root privileges are
    required, and disables Linux-only sensors that cannot run here.
    """
    state = Path(os.environ.get("ARES_STATE_DIR", Path.home() / ".ares"))
    return {
        "storage": {"path": str(state / "ares.db")},
        "sensors": {"filesystem": {"enabled": True}, "identity": {"enabled": False}},
    }


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """Load config from ``path``.

    Resolution order:
      1. Explicit ``path`` argument.
      2. ``ARES_CONFIG`` environment variable.
      3. ``DEFAULT_CONFIG_PATH`` if it exists.
      4. Built-in dev defaults (no file required).
    """
    candidate = path or os.environ.get("ARES_CONFIG") or DEFAULT_CONFIG_PATH
    candidate = Path(candidate)

    if candidate.exists():
        raw = yaml.safe_load(candidate.read_text()) or {}
        return Config.model_validate(raw)

    if path is not None:
        raise FileNotFoundError(f"Config file not found: {candidate}")

    return Config.model_validate(_dev_defaults())
