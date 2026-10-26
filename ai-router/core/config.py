"""Loads config/models.yaml and config/prompts.yaml (previously shipped but never read)."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

CONFIG_DIR = Path(os.environ.get("AI_ROUTER_CONFIG_DIR", Path(__file__).resolve().parent.parent / "config"))


def _load(name: str) -> dict[str, Any]:
    path = CONFIG_DIR / name
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@lru_cache(maxsize=1)
def models_config() -> dict[str, Any]:
    return _load("models.yaml")


@lru_cache(maxsize=1)
def prompts_config() -> dict[str, str]:
    return {k: str(v).strip() for k, v in _load("prompts.yaml").items()}
