"""
Operational Audit Trail Logger
==============================
Implements FR-16.2: an append-only, tamper-evident operational audit log.

Every investigator action (file uploads, scenario loads, parameter/threshold
changes, analysis runs, report exports) is appended as a structured JSON record.
To keep the trail tamper-evident, each record is chained to the previous record
via a SHA-256 integrity hash:

    record_n.sha256 = SHA256( record_n.payload | record_{n-1}.sha256 )

Records are stored in the ``audit_log`` table (SQLAlchemy, Postgres-compatible).
Storing in the DB (rather than a filesystem log) makes the trail work on
serverless hosts like Vercel where the filesystem is read-only/ephemeral.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import select

from app.dependencies import get_session
from app.models import AuditLog

_prev_hash_store: Dict[str, Optional[str]] = {}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _last_prev_hash(session) -> Optional[str]:
    """Read the most recent record's hash to chain the next one onto it."""
    row = session.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    ).scalars().first()
    return row.record_hash if row else None


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
    details = details or {}
    payload = {
        "ts": _utcnow(),
        "action": action,
        "actor": actor,
        "investigation_id": investigation_id,
        "details": details,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    session = get_session()
    try:
        prev = _last_prev_hash(session)
        record_hash = hashlib.sha256((payload_json + "|" + (prev or "")).encode("utf-8")).hexdigest()

        session.add(AuditLog(
            ts=payload["ts"],
            action=action,
            actor=actor,
            investigation_id=investigation_id,
            details=payload_json,
            record_hash=record_hash,
            prev_hash=prev,
        ))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    payload["record_hash"] = record_hash
    payload["prev_hash"] = prev or None
    return payload


def read_audit_log(limit: int = 500) -> List[Dict]:
    """Read and verify the audit trail, returning record dicts newest-first."""
    session = get_session()
    try:
        rows = session.execute(
            select(AuditLog).order_by(AuditLog.id.asc())
        ).scalars().all()
    finally:
        session.close()

    records: List[Dict] = []
    prev: Optional[str] = None
    for row in rows:
        try:
            payload = json.loads(row.details)
        except ValueError:
            continue
        payload_part = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256((payload_part + "|" + (prev or "")).encode("utf-8")).hexdigest()
        payload["record_hash"] = row.record_hash
        payload["prev_hash"] = row.prev_hash
        payload["chain_valid"] = expected == row.record_hash
        records.append(payload)
        prev = row.record_hash

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
    session = get_session()
    try:
        session.query(AuditLog).delete()
        session.commit()
    finally:
        session.close()
