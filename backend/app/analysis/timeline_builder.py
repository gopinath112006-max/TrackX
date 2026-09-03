"""
Timeline Builder
================
Constructs the chronological attack timeline from analyzed events.
Timeline entries are always sorted by timestamp and include both
normal and suspicious events, but suspicious events are emphasized.
"""

from datetime import datetime
from typing import Dict, List

from app.schemas.schemas import NormalizedEvent
from app.utils.helpers import parse_datetime_naive


def _parse_ts(ts_str: str) -> datetime:
    parsed = parse_datetime_naive(ts_str)
    return parsed if parsed is not None else datetime.min


def build_timeline(
    events: List[NormalizedEvent],
    include_all: bool = True,
) -> List[Dict[str, object]]:
    """
    Build a chronological timeline from the events.

    Returns a list of dicts (sorted ascending by timestamp):
      {
        "event_id": str,
        "timestamp": str,
        "display_text": str,
        "sequence_order": int,
        "severity": str,
        "details": NormalizedEvent,
      }
    """
    events_sorted = sorted(events, key=lambda e: (_parse_ts(e.timestamp), e.event_id))
    entries: List[Dict[str, object]] = []

    for idx, ev in enumerate(events_sorted):
        display_text = _render_display_text(ev)
        entries.append({
            "event_id": ev.event_id,
            "timestamp": ev.timestamp,
            "display_text": display_text,
            "sequence_order": idx,
            "severity": ev.severity,
            "details": ev,
        })

    return entries


def _render_display_text(ev: NormalizedEvent) -> str:
    """Render a concise human-readable description of an event."""
    parts = []
    if ev.user:
        parts.append(f"user '{ev.user}'")
    if ev.event_type in ("LOGIN", "LOGOUT"):
        status = ev.status or ""
        verb = "logged in" if "success" in status.lower() else "failed login"
        target = ev.destination_host or ev.source_host or ev.source_ip or ""
        source = f"from {ev.source_ip}" if ev.source_ip else ""
        text = f"{verb.capitalize()} {source} {('to ' + target) if target else ''}"
    elif ev.event_type == "FILE_ACCESS":
        text = f"accessed file '{ev.file_path}'"
    elif ev.event_type == "FILE_DOWNLOAD":
        text = f"downloaded file '{ev.file_path}'"
    elif ev.event_type == "FILE_UPLOAD":
        text = f"uploaded file '{ev.file_path}'"
    elif ev.event_type == "NETWORK_CONNECTION":
        dest = ev.destination_host or ev.destination_ip or "unknown"
        text = f"network connection to {dest}"
    elif ev.event_type == "DATA_TRANSFER":
        dest = ev.destination_ip or ev.destination_host or "external"
        text = f"data transfer to {dest}"
    elif ev.event_type == "PROCESS_EXEC":
        text = f"process execution '{ev.action}'"
    else:
        text = ev.action or ev.event_type

    base = text if not parts else f"{'} - '.join(parts)}: {text}"
    return f"{base} [{ev.event_id}]"
