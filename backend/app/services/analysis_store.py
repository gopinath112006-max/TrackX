"""
In-memory analysis store
========================
Holds the latest analysis results per investigation for the running process.
This keeps the demo simple: events persist in SQLite, while analysis
products (findings, timeline, correlations, graph, story) are cached in
memory so they can be served quickly to the frontend.

A new analysis run replaces the stored result for that investigation.
"""

import threading
from typing import Dict, List, Optional

_lock = threading.Lock()
_store: Dict[int, Dict[str, object]] = {}


def save_analysis(investigation_id: int, analysis: Dict[str, object]) -> None:
    with _lock:
        _store[investigation_id] = analysis


def get_analysis(investigation_id: int) -> Optional[Dict[str, object]]:
    with _lock:
        return _store.get(investigation_id)


def clear_analysis(investigation_id: int) -> None:
    with _lock:
        _store.pop(investigation_id, None)