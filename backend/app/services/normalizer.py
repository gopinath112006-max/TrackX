"""
Evidence Normalization Service
===============================
Takes raw parsed event dictionaries and converts them into a canonical
NormalizedEvent structure. Original raw evidence is preserved separately
so it can always be inspected later.

Forensic principle: normalized copies never overwrite the original raw
records; they are stored alongside them.
"""

from typing import Any, Dict, List, Optional

from app.schemas.schemas import NormalizedEvent
from app.utils.helpers import parse_timestamp, sanitize_input
from app.utils.parallel import parallel_map

# Default event type keywords for classification
_EVENT_TYPE_MAP = {
    "LOGIN": ["login", "logon", "auth", "authenticate", "signin"],
    "LOGOUT": ["logout", "logoff", "signout"],
    "FILE_ACCESS": ["read", "open", "view", "shown", "file access", "file accessed", "file_accessed"],
    "FILE_DOWNLOAD": ["download", "get", "fetch", "copy_out"],
    "FILE_UPLOAD": ["upload", "put", "post"],
    "NETWORK_CONNECTION": ["connect", "connection", "syn", "established", "net_connection"],
    "FILE_COPY": ["copy", "duplicate", "replicate", "cp"],
    "PROCESS_EXEC": ["process", "execute", "exec", "run", "spawn", "psexec", "process_execution"],
    "DATA_TRANSFER": ["transfer", "exfil", "drop", "send", "sent", "receive", "received", "bytes_transferred", "network_transfer"],
}


def classify_event_type(action: str, event_type: Optional[str] = None) -> str:
    """Classify an event into a canonical event type based on keywords."""
    if event_type:
        et = event_type.upper()
        for key, keywords in _EVENT_TYPE_MAP.items():
            for kw in keywords:
                if kw.upper() in et:
                    return key
    action_l = (action or "").lower()
    for key, keywords in _EVENT_TYPE_MAP.items():
        for kw in keywords:
            if kw in action_l:
                return key
    return "SYSTEM"


def normalize_event(raw: Dict[str, Any], source: Optional[str] = None) -> NormalizedEvent:
    """
    Convert a raw parsed event dict into a canonical NormalizedEvent.
    Never mutates the raw dict; produces a new normalized object.
    """
    event_type = classify_event_type(
        str(raw.get("action", "")),
        str(raw.get("event_type", "")),
    )

    ts = parse_timestamp(str(raw.get("timestamp", ""))) or str(raw.get("timestamp", ""))

    # Preserve the original raw evidence record for forensic inspection.
    # The parser embeds it under 'raw_data'; unwrap it so the normalized event's
    # raw_data field holds the true original record (the uploaded row).
    embedded = raw.get("raw_data")
    if isinstance(embedded, dict):
        raw_copy = dict(embedded)
    else:
        raw_copy = dict(raw)

    # Preserve the immutable provenance pointer (FR-02.3) when present.
    raw_ref = None
    rr = raw.get("raw_ref")
    if isinstance(rr, dict) and rr.get("file_hash") and rr.get("line_index") is not None:
        raw_ref = {
            "file_hash": str(rr["file_hash"]),
            "line_index": int(rr["line_index"]),
        }

    return NormalizedEvent(
        event_id=sanitize_input(str(raw.get("event_id", "")), 50),
        timestamp=ts,
        event_type=event_type,
        user=_safe_str(raw.get("user")),
        source_ip=_safe_str(raw.get("source_ip")),
        destination_ip=_safe_str(raw.get("destination_ip")),
        source_host=_safe_str(raw.get("source_host")),
        destination_host=_safe_str(raw.get("destination_host")),
        file_path=_safe_str(raw.get("file_path")),
        action=sanitize_input(str(raw.get("action", "UNKNOWN"))) or "UNKNOWN",
        status=_safe_str(raw.get("status")),
        severity=(_safe_str(raw.get("severity")) or "INFO").upper(),
        source=_safe_str(source) or _safe_str(raw.get("source")),
        raw_ref=raw_ref,
        raw_data=raw_copy,
    )


def normalize_events(raw_events: List[Dict[str, Any]], source: Optional[str] = None) -> List[NormalizedEvent]:
    """Normalize a list of raw event dictionaries (parallel, order-preserving NFR-P-02).

    `normalize_event` is a pure function of each raw dict (event IDs are
    pre-assigned by the parser), so it is embarrassingly parallel while
    remaining deterministic (NFR-R-01).
    """
    return parallel_map(lambda ev: normalize_event(ev, source), raw_events)


def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return sanitize_input(s) if s else None
