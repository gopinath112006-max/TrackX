"""Event retrieval & search endpoints."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import Event
from app.schemas.schemas import EventFilters, EventResponse
from app.utils.helpers import safe_json_loads

router = APIRouter(prefix="/api", tags=["events"])


def _to_response(ev: Event) -> EventResponse:
    return EventResponse(
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
        raw_ref=safe_json_loads(ev.raw_ref, default=None),
        raw_data=safe_json_loads(ev.raw_data, default={}),
    )


@router.get("/events", response_model=List[EventResponse])
def list_events(
    investigation_id: int,
    user: Optional[str] = None,
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    """List events with optional filters."""
    stmt = select(Event).where(Event.investigation_id == investigation_id)

    if user:
        stmt = stmt.where(Event.user == user)
    if source_ip:
        stmt = stmt.where(Event.source_ip == source_ip)
    if event_type:
        stmt = stmt.where(Event.event_type == event_type)
    if severity:
        stmt = stmt.where(Event.severity == severity)
    if status:
        stmt = stmt.where(Event.status == status)
    if source:
        stmt = stmt.where(Event.source == source)
    if start_time:
        stmt = stmt.where(Event.timestamp >= start_time)
    if end_time:
        stmt = stmt.where(Event.timestamp <= end_time)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            (Event.user.like(like)) | (Event.source_ip.like(like))
            | (Event.destination_ip.like(like))
            | (Event.event_id.like(like))
            | (Event.file_path.like(like))
        )

    stmt = stmt.order_by(Event.timestamp).limit(limit)
    rows = db.execute(stmt).scalars().all()
    return [_to_response(r) for r in rows]


@router.get("/events/{event_id}", response_model=EventResponse)
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
):
    """Fetch a single event by its event_id."""
    row = db.execute(select(Event).where(Event.event_id == event_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return _to_response(row)


@router.post("/events/filter", response_model=List[EventResponse])
def filter_events(
    investigation_id: int,
    filters: EventFilters,
    db: Session = Depends(get_db),
):
    """Apply structured filters to the events."""
    stmt = select(Event).where(Event.investigation_id == investigation_id)

    if filters.user:
        stmt = stmt.where(Event.user == filters.user)
    if filters.source_ip:
        stmt = stmt.where(Event.source_ip == filters.source_ip)
    if filters.event_type:
        stmt = stmt.where(Event.event_type == filters.event_type)
    if filters.severity:
        stmt = stmt.where(Event.severity == filters.severity)
    if filters.start_time:
        stmt = stmt.where(Event.timestamp >= filters.start_time)
    if filters.end_time:
        stmt = stmt.where(Event.timestamp <= filters.end_time)
    if filters.search:
        like = f"%{filters.search}%"
        stmt = stmt.where(
            (Event.user.like(like)) | (Event.source_ip.like(like))
            | (Event.destination_ip.like(like))
            | (Event.event_id.like(like))
            | (Event.file_path.like(like))
        )

    stmt = stmt.order_by(Event.timestamp)
    rows = db.execute(stmt).scalars().all()
    return [_to_response(r) for r in rows]