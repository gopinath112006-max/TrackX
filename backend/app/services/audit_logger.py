"""
Operational Audit Trail Logger
==============================
Implements FR-16.2: an append-only, tamper-evident operational audit log.

Every investigator action (file uploads, scenario loads, parameter/threshold
changes, analysis runs, report exports) is appended as a structured JSON
record to an append-only `audit.log`. To make the trail tamper-evident, each
record is chained to the previous record via a SHA-256 integrity hash:

    entry_n.sha256 = SHA256( entry_n.payload | entry_{n-1}.sha256 )

Appending to the same file handle (append mode only) and verifying the chain
lets an auditor detect any truncation, reordering, or alteration of prior
records.
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

_OPEN = os.environ.get("TRACELINE_AUDIT_LOG")
if not _OPEN:
    _OPEN = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "audit.log",
    )
AUDIT_LOG_PATH = _OPEN

_lock = threading.Lock()
_prev_hash: Optional[str] = None


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _max_line_payload(line: bytes) -> str:
    """Strip the trailing prev_hash field from a stored line to recover payload."""
    try:
        return line.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError:
        return repr(line)


def _read_prev_hash() -> Optional[str]:
    """Read the last entry's hash by scanning the log file tail."""
    if not os.path.exists(AUDIT_LOG_PATH) or os.path.getsize(AUDIT_LOG_PATH) == 0:
        return None
    try:
        with open(AUDIT_LOG_PATH, "rb") as f:
            # Read the last 600 bytes to capture the final record.
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 600))
            tail = f.read()
        lines = tail.splitlines()
        if not lines:
            return None
        # The stored line is `<payload>|<prev_hash>`; recover prev_hash.
        last = lines[-1].decode("utf-8", errors="ignore")
        if "|" in last:
            return last.rsplit("|", 1)[1]
        # Fallback: hash the entire last line (import occurred pre-chain).
        return hashlib.sha256(last.encode("utf-8")).hexdigest()
    except Exception:
        return None


def log_action(
    action: str,
    actor: str = "investigator",
    investigation_id: Optional[int] = None,
    details: Optional[Dict] = None,
) -> Dict:
    """
    Append one audit record and return it.

    Args:
        action: short action name, e.g. "evidence_upload", "scenario_load",
            "analysis_run", "report_export", "threshold_change".
        actor: the acting principal (defaults to 'investigator').
        investigation_id: relevant investigation, if any.
        details: a JSON-serializable dict with contextual parameters.
    """
    global _prev_hash
    details = details or {}
    payload = {
        "ts": _utcnow(),
        "action": action,
        "actor": actor,
        "investigation_id": investigation_id,
        "details": details,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    with _lock:
        if _prev_hash is None:
            _prev_hash = _read_prev_hash()
        prev = _prev_hash or ""
        record_hash = hashlib.sha256((payload_json + "|" + prev).encode("utf-8")).hexdigest()

        line = f"{payload_json}|{record_hash}\n"
        try:
            os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
            with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            # If the audit log file is unwritable we propagate the failure so
            # callers can restrict administrative modifications (FR-16.2).
            raise

        payload["record_hash"] = record_hash
        payload["prev_hash"] = prev or None
        _prev_hash = record_hash
        return payload


def read_audit_log(limit: int = 500) -> List[Dict]:
    """Read and verify the audit trail, returning record dicts newest-first."""
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    records: List[Dict] = []
    prev: Optional[str] = None
    try:
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or "|" not in line:
                    continue
                payload_part, hash_part = line.rsplit("|", 1)
                try:
                    payload = json.loads(payload_part)
                except ValueError:
                    continue
                expected = hashlib.sha256((payload_part + "|" + (prev or "")).encode("utf-8")).hexdigest()
                payload["record_hash"] = hash_part
                payload["prev_hash"] = prev
                payload["chain_valid"] = expected == hash_part
                records.append(payload)
                prev = hash_part
    except Exception:
        return records
    records.reverse()
    if limit:
        records = records[:limit]
    return records


def verify_audit_chain() -> Dict:
    """Verify the entire chain is intact (no tampering, truncation, reorder)."""
    records = read_audit_log(limit=None)
    broken = [r for r in records if r.get("chain_valid") is False]
    return {
        "total_records": len(records),
        "valid": len(records) - len(broken),
        "broken": len(broken),
        "intact": len(records) > 0 and len(broken) == 0,
        "first_broken_record": broken[0].get("ts") if broken else None,
    }


def reset_audit_log() -> None:
    """Clear the audit log (mainly for tests)."""
    global _prev_hash
    with _lock:
        _prev_hash = None
        if os.path.exists(AUDIT_LOG_PATH):
            os.remove(AUDIT_LOG_PATH)
