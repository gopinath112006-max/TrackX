"""
Evidence Parser
===============
Responsible for reading uploaded evidence files (CSV, JSON, TXT) and
converting them into raw normalized event dictionaries.

Forensic principle: the original evidence is never modified. We only read
the bytes, and produce normalized copies.
"""

import csv
import hashlib
import io
import json
import re
from typing import Any, Dict, List, Optional

from app.utils.helpers import parse_timestamp, sanitize_input
from app.utils.parallel import parallel_map


# Mapping of header keywords to canonical NormalizedEvent fields.
# Lookup is case-insensitive and tolerant of prefixes/suffixes.
_HEADER_MAP = {
    "timestamp": ["timestamp", "time", "datetime", "date", "log_time", "event_time", "ts"],
    "user": ["user", "username", "user_name", "account", "login_id", "user_id", "principal"],
    "source_ip": ["source_ip", "src_ip", "sourceip", "ip", "ip_address", "src", "from_ip", "client_ip", "remote_ip", "source_address"],
    "destination_ip": ["destination_ip", "dst_ip", "dest_ip", "to_ip", "target_ip", "destination_address"],
    "source_host": ["source_host", "src_host", "sourcehost", "host", "hostname", "computer", "host_name", "src_hostname", "device"],
    "destination_host": ["destination_host", "dst_host", "dest_host", "target_host", "destination_hostname", "server"],
    "file_path": ["file", "filename", "file_name", "file_path", "path", "object", "resource", "document", "file_accessed", "file_accessed"],
    "action": ["action", "event", "event_type_label", "operation", "activity", "type", "verb"],
    "status": ["status", "result", "outcome", "success", "auth_result", "login_status", "state"],
    "event_type": ["event_type", "category", "log_type", "source_type", "event_category", "type", "rule"],
    "severity": ["severity", "level", "priority", "risk", "importance"],
    "destination_port": ["destination_port", "dst_port", "port"],
    "bytes": ["bytes", "bytes_transferred", "size", "data_size", "transfer_size", "volume", "bytes_sent", "bytes_received"],
}

# Canonical event categories -> list of acceptable category labels
_CATEGORY_KEYWORDS = {
    "login": ["login", "auth", "authentication", "account", "logon", "authentication"],
    "file_access": ["file", "access", "document", "filesystem", "file_access"],
    "network": ["network", "traffic", "connection", "transfer", "flow", "netflow"],
    "system": ["system", "event", "process", "os", "kernel", "system_log", "syslog"],
    "database": ["database", "db", "sql", "query"],
}


def detect_category(filename: str, sample_row: Optional[Dict[str, Any]] = None) -> str:
    """
    Detect the evidence category based on the filename or content keywords.
    Returns one of: login, file_access, network, system, database.
    """
    name_lower = filename.lower()

    for category, keywords in _CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in name_lower:
                return category

    # Fallback: inspect content keywords
    if sample_row:
        row_text = " ".join(f"{k} {str(v)}".lower() for k, v in sample_row.items())
        for category, keywords in _CATEGORY_KEYWORDS.items():
            for keyword in keywords:
                if keyword in row_text:
                    return category

    return "system"


def _map_headers(headers: List[str]) -> Dict[str, str]:
    """Build a mapping of canonical field -> original column name."""
    mapping: Dict[str, str] = {}
    normalized_headers = {}
    for h in headers:
        if h is None:
            continue
        h_lower = h.strip().lower()
        normalized_headers[h_lower] = h.strip()

    for canonical, aliases in _HEADER_MAP.items():
        for alias in aliases:
            if alias in normalized_headers:
                mapping[canonical] = normalized_headers[alias]
                break

    return mapping


def _row_to_event(
    row: Dict[str, Any],
    mapping: Dict[str, str],
    source_filename: str,
    event_id: str,
    raw_ref: Dict[str, Any],
) -> Dict[str, Any]:
    """Convert a raw row dict into a normalized event dictionary based on the header mapping.

    `raw_ref` is the immutable provenance pointer `{"file_hash", "line_index"}`
    computed from the ingested file's SHA-256 hash and the record's line index.
    `event_id` is precomputed by the caller so this function is a pure function
    of its inputs (enabling deterministic parallel mapping, NFR-P-02 / NFR-R-01).
    """
    def get(canonical: str) -> Optional[str]:
        col = mapping.get(canonical)
        if col is None or col not in row:
            return None
        val = row[col]
        return sanitize_input(str(val)) if val is not None else None

    raw = {k: v for k, v in row.items()}

    ts = get("timestamp")
    event_type = get("event_type")
    action = get("action")
    status = get("status")

    # If event_type is empty, derive from action
    if not event_type and action:
        event_type = action.upper().replace(" ", "_")

    # If action is empty, derive from event_type
    if not action and event_type:
        action = event_type.replace("_", " ").title()

    parsed_ts = parse_timestamp(ts) or ts

    # Determine severity: explicit or inferred
    severity = get("severity") or _infer_severity(action, status)

    return {
        "event_id": event_id,
        "timestamp": parsed_ts or "",
        "event_type": (event_type or action or "UNKNOWN").upper(),
        "user": get("user"),
        "source_ip": get("source_ip"),
        "destination_ip": get("destination_ip"),
        "source_host": get("source_host"),
        "destination_host": get("destination_host"),
        "file_path": get("file_path"),
        "action": (action or "UNKNOWN"),
        "status": status,
        "severity": severity,
        "source": source_filename,
        "raw_ref": raw_ref,
        "raw_data": raw,
    }


def _infer_severity(action: str, status: Optional[str]) -> str:
    """Infer a severity level from the action/status when none is provided."""
    action_l = (action or "").lower()
    status_l = (status or "").lower()

    if "failed" in action_l or ("fail" in status_l):
        return "CRITICAL"
    if "delete" in action_l or "drop" in action_l or "transfer" in action_l or "download" in action_l:
        return "MEDIUM"
    if "error" in status_l or "denied" in status_l or "reject" in status_l:
        return "HIGH"
    return "INFO"


def parse_csv(content: bytes, filename: str) -> List[Dict[str, Any]]:
    """Parse CSV content into a list of normalized events.

    Computes the SHA-256 hash of the source file bytes once and attaches an
    immutable `raw_ref` (file_hash + line_index) to every generated event so
    each canonical record traces to its exact origin row (FR-02.3).
    """
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    file_hash = hashlib.sha256(content).hexdigest()

    reader = csv.DictReader(io.StringIO(text))
    headers = reader.fieldnames or []
    if not headers:
        raise ValueError("CSV file has no headers")

    mapping = _map_headers(headers)

    # Gather (event_id, row, raw_ref) tuples up-front. Event IDs and line
    # indices are assigned sequentially BEFORE any parallel work so that the
    # output order and IDs are fully deterministic (FR-02.3, NFR-R-01).
    indexed_rows: List[tuple] = []
    counter = 0
    line_index = 1
    for row in reader:
        line_index += 1
        if not row or all(v is None or str(v).strip() == "" for v in row.values()):
            continue
        counter += 1
        raw_ref = {"file_hash": file_hash, "line_index": line_index}
        indexed_rows.append((counter, dict(row), raw_ref))

    def _convert(item: tuple) -> Dict[str, Any]:
        ctr, row, raw_ref = item
        return _row_to_event(row, mapping, filename, f"EVT-{ctr:04d}", raw_ref)

    return parallel_map(_convert, indexed_rows)


def parse_json(content: bytes, filename: str) -> List[Dict[str, Any]]:
    """Parse JSON content (either an array or an object with an events key).

    Attaches an immutable `raw_ref` (file_hash + record index) to every event
    (FR-02.3).
    """
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid JSON: {e}")

    file_hash = hashlib.sha256(content).hexdigest()

    events_raw: List[Dict[str, Any]] = []
    if isinstance(data, list):
        events_raw = data
    elif isinstance(data, dict):
        for key in ("events", "logs", "records", "data", "items"):
            if isinstance(data.get(key), list):
                events_raw = data[key]
                break
        if not events_raw and len(data) > 0:
            # Maybe a single event object
            events_raw = [data]

    counter = [0]
    events = []
    # Build a mapping for the first event to infer header names
    if events_raw:
        sample = events_raw[0]
        headers = list(sample.keys()) if isinstance(sample, dict) else []
        mapping = _map_headers(headers)
    else:
        mapping = {}

    # Precompute sequential event IDs before any parallel work (determinism).
    indexed: List[tuple] = []
    for idx, ev in enumerate(events_raw, start=1):
        if not isinstance(ev, dict):
            continue
        indexed.append((idx, ev, {"file_hash": file_hash, "line_index": idx}))

    def _convert(item: tuple) -> Dict[str, Any]:
        idx, ev, raw_ref = item
        return _row_to_event(ev, mapping, filename, f"EVT-{idx:04d}", raw_ref)

    return parallel_map(_convert, indexed)


def parse_txt(content: bytes, filename: str) -> List[Dict[str, Any]]:
    """
    Parse a plain-text log file with key=value pairs on each line.
    Format per line: timestamp=... user=... action=... status=... etc.

    Attaches an immutable `raw_ref` (file_hash + line_index) to every event
    (FR-02.3).
    """
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    file_hash = hashlib.sha256(content).hexdigest()

    indexed: List[tuple] = []
    counter = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Parse key=value pairs
        row = {}
        for part in re.split(r"[;\t]\s*|\s{2,}", line):
            if "=" in part:
                key, _, val = part.partition("=")
                row[key.strip().lower()] = val.strip()
        if row:
            counter += 1
            indexed.append((counter, row, {"file_hash": file_hash, "line_index": line_number}))

    def _convert(item: tuple) -> Dict[str, Any]:
        ctr, row, raw_ref = item
        headers = list(row.keys())
        mapping = _map_headers(headers)
        return _row_to_event(row, mapping, filename, f"EVT-{ctr:04d}", raw_ref)

    return parallel_map(_convert, indexed)


def parse_evidence(content: bytes, filename: str) -> List[Dict[str, Any]]:
    """Route to the correct parser based on file extension."""
    filename_lower = filename.lower()
    if filename_lower.endswith(".csv"):
        return parse_csv(content, filename)
    elif filename_lower.endswith(".json"):
        return parse_json(content, filename)
    elif filename_lower.endswith(".txt"):
        return parse_txt(content, filename)
    else:
        # Try to detect by content
        try:
            text = content.decode("utf-8-sig").lstrip()
            if text.startswith("{") or text.startswith("["):
                return parse_json(content, filename)
            elif "," in text.split("\n", 1)[0]:
                return parse_csv(content, filename)
            else:
                return parse_txt(content, filename)
        except Exception:
            raise ValueError(f"Unsupported file format: {filename}")
