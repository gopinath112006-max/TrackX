"""
TraceLine Configuration Loader
==============================
Loads externalized analysis heuristics from `config/analysis_config.yaml`
(NFR-M-03). Enables forensic experts to tune detection thresholds, confidence
weights, and correlation windows without modifying source code.

The configuration path can be overridden with the `TRACELINE_CONFIG`
environment variable; the default is `config/analysis_config.yaml` relative
to this package.
"""

import os
from typing import Any, Dict, Optional

import yaml

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG_PATH = os.path.join("config", "analysis_config.yaml")


def _default_path() -> str:
    env = os.environ.get("TRACELINE_CONFIG")
    if env:
        return env
    return os.path.join(BACKEND_DIR, DEFAULT_CONFIG_PATH)


def _load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


class Config:
    """Thin, read-only wrapper around the loaded YAML configuration."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data or {}
        self._source = ""

    def __getattr__(self, name: str) -> Any:
        # Allow dot access to top-level sections (e.g. config.confidence).
        if name in self._data:
            return self._data[name]
        raise AttributeError(name)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Return a nested value via a dotted path, e.g. 'confidence.weights.w_corroboration'."""
        node: Any = self._data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def as_dict(self) -> Dict[str, Any]:
        return self._data

    @property
    def source(self) -> str:
        return self._source


_config: Optional[Config] = None


def get_config() -> Config:
    """Return the cached, loaded configuration (idempotent & deterministic)."""
    global _config
    if _config is None:
        path = _default_path()
        cfg = Config(_load(path))
        cfg._source = path
        _config = cfg
    return _config


def _nested_get(root: Dict[str, Any], keys: list, default: Any) -> Any:
    node: Any = root
    for k in keys:
        if not isinstance(node, dict) or k not in node:
            return default
        node = node[k]
    return node


# --- Convenience accessors used by the analysis modules ----------------------
# Each returns the externalized value with a fallback to the prior hardcoded
# default so behavior is preserved even if a config file is absent/malformed.


def conf_float(key: str, default: float) -> float:
    val = get_config().get(key)
    return float(val) if isinstance(val, (int, float)) else default


def conf_int(key: str, default: int) -> int:
    val = get_config().get(key)
    return int(val) if isinstance(val, (int, float)) and not isinstance(val, bool) else default


def conf_str(key: str, default: str) -> str:
    val = get_config().get(key)
    return str(val) if isinstance(val, str) else default


def conf_list(key: str, default: list) -> list:
    val = get_config().get(key)
    return list(val) if isinstance(val, list) else default


def conf_dict(key: str, default: dict) -> dict:
    val = get_config().get(key)
    return dict(val) if isinstance(val, dict) else default
