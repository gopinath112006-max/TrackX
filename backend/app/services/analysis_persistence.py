"""
Analysis persistence
====================
Persists analysis products (findings, correlations, timeline entries,
relationships) to SQLite so they survive a server restart and provide a
materialized forensics record per investigation.

The analysis pipeline is deterministic: the same persisted events always
produce the same analysis output.  `restore_analysis` therefore re-runs the
pipeline over the persisted events and repopulates the in-memory store.
"""

from typing import Dict, List, Optional

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.analysis.engine import run_analysis
from app.models import (
    Correlation,
    Event,
    Finding,
    Relationship,
    TimelineEntry,
)
from app.utils.helpers import safe_json_dumps


def persist_analysis(db: Session, investigation_id: int, result: Dict[str, object]) -> None:
    """Write all analysis products for an investigation into SQLite (replace)."""
    # Use synchronize_session="fetch" so rows deleted at the DB level are also
    # expunged from the session's identity map. Without it, previously-loaded
    # ORM objects keep their identities, and SQLite reuses their freed rowids
    # for the new inserts below, causing the SQLAlchemy identity-map collision
    # warning ("Identity map already had an identity for ...") on commit.
    for model in (Finding, Correlation, TimelineEntry, Relationship):
        db.execute(
            delete(model)
            .where(model.investigation_id == investigation_id)
            .execution_options(synchronize_session="fetch")
        )

    for f in result.get("findings", []):
        db.add(Finding(
            investigation_id=investigation_id,
            finding_id=f["finding_id"],
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            confidence=f["confidence"],
            related_event_ids=safe_json_dumps(f.get("related_event_ids", [])),
            reason=f["reason"],
            category=f.get("category", "unknown"),
        ))

    for c in result.get("correlations", []):
        db.add(Correlation(
            investigation_id=investigation_id,
            event_a_event_id=c["event_a_event_id"],
            event_b_event_id=c["event_b_event_id"],
            score=c["score"],
            factors=safe_json_dumps(c.get("factors", [])),
        ))

    for t in result.get("timeline", []):
        db.add(TimelineEntry(
            investigation_id=investigation_id,
            event_id=t["event_id"],
            timestamp=t["timestamp"],
            display_text=t["display_text"],
            sequence_order=t["sequence_order"],
            severity=t["severity"],
        ))

    node_types = {n["id"]: n.get("type", "EVENT") for n in result.get("graph", {}).get("nodes", [])}
    for e in result.get("graph", {}).get("edges", []):
        db.add(Relationship(
            investigation_id=investigation_id,
            source_node=e["source"],
            target_node=e["target"],
            source_type=node_types.get(e["source"], "EVENT"),
            target_type=node_types.get(e["target"], "EVENT"),
            relationship_type=e.get("label", "related_to"),
            evidence_event_ids=safe_json_dumps(e.get("evidence_event_ids", [])),
        ))

    db.commit()


def has_persisted_analysis(db: Session, investigation_id: int) -> bool:
    """Whether any analysis products are stored for the investigation."""
    return db.execute(
        select(Finding.id).where(Finding.investigation_id == investigation_id).limit(1)
    ).scalar_one_or_none() is not None


def load_events_from_db(db: Session, investigation_id: int) -> List[Dict[str, object]]:
    """Reconstruct the event list consumed by the analysis pipeline."""
    from app.schemas.schemas import EventResponse
    from app.utils.helpers import safe_json_loads

    rows = db.execute(
        select(Event).where(Event.investigation_id == investigation_id)
    ).scalars().all()
    events = []
    for ev in rows:
        events.append(EventResponse(
            id=ev.id,
            event_id=ev.event_id,
            timestamp=ev.timestamp,
            event_type=ev.event_type,
            user=ev.user,
            source_ip=ev.source_ip,
            destination_ip=ev.destination_ip,
            source_host=ev.source_host,
            destination_host=ev.destination_host,
            file_path=ev.file_path,
            action=ev.action,
            status=ev.status,
            severity=ev.severity,
            source=ev.source,
            raw_ref=safe_json_loads(ev.raw_ref, None),
            raw_data=safe_json_loads(ev.raw_data, {}),
        ))
    return events


def restore_analysis(db: Session, investigation_id: int) -> Optional[Dict[str, object]]:
    """
    Rebuild the full analysis result for a previously-analyzed investigation.

    Returns None when no persisted analysis exists (analysis was never run).
    """
    if not has_persisted_analysis(db, investigation_id):
        return None

    events = load_events_from_db(db, investigation_id)
    result = run_analysis(events)
    from app.services import analysis_store
    analysis_store.save_analysis(investigation_id, result)
    return result