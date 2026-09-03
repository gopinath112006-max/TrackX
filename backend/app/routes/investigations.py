"""Investigation management endpoints."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import Investigation, EvidenceFile, Event
from app.schemas.schemas import InvestigationSummary, FindingResponse, ScenarioInfo
from app.services import analysis_store, analysis_persistence
from app.services.scenario_loader import list_scenarios

router = APIRouter(prefix="/api", tags=["investigations"])

# Track the currently-active investigation id for the demo
_ACTIVE_INVESTIGATION = {"id": None}


def _get_analysis(investigation_id: int, db: Session):
    """Return analysis results from the cache, restoring from SQLite on miss."""
    analysis = analysis_store.get_analysis(investigation_id)
    if analysis is not None:
        return analysis
    return analysis_persistence.restore_analysis(db, investigation_id)


def set_active_investigation(investigation_id: int):
    _ACTIVE_INVESTIGATION["id"] = investigation_id


def get_active_investigation_id() -> int:
    return _ACTIVE_INVESTIGATION["id"]


@router.post("/investigations")
def create_investigation(
    name: str = "Untitled Investigation",
    scenario_type: str | None = None,
    db: Session = Depends(get_db),
):
    """Create a new investigation."""
    inv = Investigation(name=name, scenario_type=scenario_type)
    db.add(inv)
    db.commit()
    db.refresh(inv)
    set_active_investigation(inv.id)
    return {"id": inv.id, "name": inv.name, "message": "Investigation created"}


@router.get("/investigations", response_model=List[InvestigationSummary])
def list_investigations(db: Session = Depends(get_db)):
    """List all investigations with summary counts."""
    rows = db.execute(select(Investigation).order_by(Investigation.created_at.desc())).scalars().all()
    results = []
    for inv in rows:
        total = db.execute(
            select(Event).where(Event.investigation_id == inv.id)
        ).scalars().all()
        analysis = _get_analysis(inv.id, db) or {}
        findings = analysis.get("findings", [])
        summary = InvestigationSummary(
            id=inv.id,
            name=inv.name,
            scenario_type=inv.scenario_type,
            status=inv.status,
            risk_level=inv.risk_level,
            confidence=inv.confidence,
            total_events=len(total),
            suspicious_events=len(findings),
            affected_users=analysis.get("blast_radius", {}).get("users", []),
            affected_ips=analysis.get("blast_radius", {}).get("ips", []),
            affected_hosts=analysis.get("blast_radius", {}).get("hosts", []),
            affected_files=analysis.get("blast_radius", {}).get("files", []),
            total_findings=len(findings),
            created_at=str(inv.created_at),
        )
        if analysis.get("entry_point"):
            ep = analysis["entry_point"]
            summary.initial_entry_point = FindingResponse(
                id=-1,
                finding_id="EP",
                title="Likely initial entry point",
                description=(
                    f"{ep.get('description', 'Suspicious activity')} - "
                    f"event {ep.get('event_id', '')}, user '{ep.get('user', '')}' "
                    f"from {ep.get('source_ip', 'unknown')} at {ep.get('timestamp', 'unknown')}"
                ),
                severity="HIGH",
                confidence=ep.get("confidence", 0),
                related_event_ids=ep.get("related_event_ids", []),
                reason=" | ".join(ep.get("reasoning", [])),
                category="entry_point",
            )
        else:
            summary.initial_entry_point = None
        results.append(summary)
    return results


@router.get("/investigations/{investigation_id}", response_model=InvestigationSummary)
def get_investigation(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Get details for a specific investigation."""
    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    events = db.execute(
        select(Event).where(Event.investigation_id == investigation_id)
    ).scalars().all()
    analysis = _get_analysis(investigation_id, db) or {}

    findings = analysis.get("findings", [])
    ep = analysis.get("entry_point")

    summary = InvestigationSummary(
        id=inv.id,
        name=inv.name,
        scenario_type=inv.scenario_type,
        status=inv.status,
        risk_level=inv.risk_level,
        confidence=inv.confidence,
        total_events=len(events),
        suspicious_events=len(findings),
        affected_users=analysis.get("blast_radius", {}).get("users", []),
        affected_ips=analysis.get("blast_radius", {}).get("ips", []),
        affected_hosts=analysis.get("blast_radius", {}).get("hosts", []),
        affected_files=analysis.get("blast_radius", {}).get("files", []),
        total_findings=len(findings),
        created_at=str(inv.created_at),
    )
    if ep:
        summary.initial_entry_point = FindingResponse(
            id=-1,
            finding_id="EP",
            title="Likely initial entry point",
            description=(
                f"{ep.get('description', 'Suspicious activity')} - "
                f"event {ep.get('event_id', '')}, user '{ep.get('user', '')}' "
                f"from {ep.get('source_ip', 'unknown')} at {ep.get('timestamp', 'unknown')}"
            ),
            severity="HIGH",
            confidence=ep.get("confidence", 0),
            related_event_ids=ep.get("related_event_ids", []),
            reason=" | ".join(ep.get("reasoning", [])),
            category="entry_point",
        )
    return summary


@router.get("/scenarios", response_model=List[ScenarioInfo])
def scenarios():
    """List all demo scenarios."""
    return [ScenarioInfo(**{k: s[k] for k in ScenarioInfo.model_fields.keys() if k in s}) for s in list_scenarios()]


def _count_events_for_scenario(scenario_id: str) -> int:
    for s in list_scenarios():
        if s["id"] == scenario_id:
            return s.get("event_count", 0)
    return 0