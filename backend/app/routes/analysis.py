"""Analysis endpoints: trigger analysis, fetch findings/timeline/relationships/report."""
import os
import shutil

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import Event, Investigation, EvidenceFile, Relationship
from app.utils.helpers import safe_json_loads
from app.services import analysis_store, analysis_persistence
from app.analysis.engine import run_analysis
from app.analysis.timeline_builder import build_timeline
from app.analysis.relationship_builder import build_relationship_graph
from app.schemas.schemas import (
    AnalysisResult,
    AttackStoryResponse,
    BlastRadius,
    ConfidenceDetail,
    FindingResponse,
    RelationshipGraphResponse,
    ReportData,
    TimelineEntrySchema,
    TimelineResponse,
)
from app.services.evidence_parser import parse_evidence
from app.services.normalizer import normalize_events
from app.services.report_generator import generate_report_html
from app.services.scenario_loader import get_scenario_files
from app.services.audit_logger import log_action

router = APIRouter(prefix="/api", tags=["analysis"])


def _get_analysis(investigation_id: int, db: Session):
    """Return analysis results from the cache, restoring from SQLite on miss."""
    analysis = analysis_store.get_analysis(investigation_id)
    if analysis is not None:
        return analysis
    return analysis_persistence.restore_analysis(db, investigation_id)


def _load_events_from_db(investigation_id: int, db: Session):
    return analysis_persistence.load_events_from_db(db, investigation_id)


@router.post("/scenarios/{scenario_id}/load", response_model=AnalysisResult)
def load_scenario(
    scenario_id: str,
    create_new: bool = True,
    db: Session = Depends(get_db),
):
    """
    Load the demo scenario data into an investigation and run analysis.
    """
    files = get_scenario_files(scenario_id)
    if not files:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")

    # Find scenario name for the investigation
    from app.services.scenario_loader import list_scenarios
    scenario_name = scenario_id
    for s in list_scenarios():
        if s["id"] == scenario_id:
            scenario_name = s.get("name", scenario_id)
            break

    # Remove events of existing investigation if reusing id 1 (fresh reload)
    inv = db.execute(
        select(Investigation).where(Investigation.scenario_type == scenario_id).order_by(Investigation.id.desc())
    ).scalars().first()

    if inv is None:
        inv = Investigation(name=scenario_name, scenario_type=scenario_id)
        db.add(inv)
        db.commit()
        db.refresh(inv)

    investigation_id = inv.id

    # Reset events + evidence for a clean reload
    db.execute(Event.__table__.delete().where(Event.investigation_id == investigation_id))
    db.execute(EvidenceFile.__table__.delete().where(EvidenceFile.investigation_id == investigation_id))
    inv.status = "pending"
    inv.risk_level = "UNKNOWN"
    inv.confidence = 0.0
    db.commit()

    for file_info in files:
        filepath = file_info["path"]
        filename = file_info["filename"]
        ext = filename.lower().rsplit(".", 1)[-1]
        if ext not in ("csv", "json", "txt"):
            continue
        with open(filepath, "rb") as f:
            content = f.read()

        try:
            raw_events = parse_evidence(content, filename)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse {filename}: {e}")

        normalized = normalize_events(raw_events, source=filename)
        raw_events = [ev.model_dump() for ev in normalized]

        from app.utils.helpers import sha256_file
        file_hash = sha256_file(content)

        db.add(EvidenceFile(
            investigation_id=investigation_id,
            filename=filename,
            category=file_info.get("category", "system"),
            sha256_hash=file_hash,
            event_count=len(raw_events),
        ))

        max_id = 0
        existing = db.execute(
            select(Event.event_id).where(Event.investigation_id == investigation_id)
        ).scalars().all()
        for eid in existing:
            try:
                num = int(eid.split("-")[1])
                max_id = max(max_id, num)
            except (IndexError, ValueError):
                continue

        for i, ev in enumerate(raw_events):
            new_id = f"EVT-{max_id + i + 1:04d}"
            ev["event_id"] = new_id
            db.add(Event(
                investigation_id=investigation_id,
                event_id=ev["event_id"],
                timestamp=ev["timestamp"],
                event_type=ev["event_type"],
                user=ev.get("user"),
                source_ip=ev.get("source_ip"),
                destination_ip=ev.get("destination_ip"),
                source_host=ev.get("source_host"),
                destination_host=ev.get("destination_host"),
                file_path=ev.get("file_path"),
                action=ev.get("action"),
                status=ev.get("status"),
                severity=ev.get("severity"),
                source=ev.get("source") or filename,
                raw_ref=__import__("app.utils.helpers", fromlist=["safe_json_dumps"]).safe_json_dumps(ev.get("raw_ref")),
                raw_data=__import__("app.utils.helpers", fromlist=["safe_json_dumps"]).safe_json_dumps(ev.get("raw_data")),
            ))
    db.commit()

    # Run analysis
    result = _run_and_store_analysis(investigation_id, db)

    log_action(
        action="scenario_load",
        investigation_id=investigation_id,
        details={
            "scenario": scenario_id,
            "findings": result["counts"]["findings"],
            "events": result["counts"]["total_events"],
        },
    )

    return AnalysisResult(
        message=f"Scenario '{scenario_name}' loaded. Analysis complete.",
        investigation_id=investigation_id,
        findings_count=result["counts"]["findings"],
        timeline_count=result["counts"]["timeline_entries"],
        relationships_count=result["counts"]["graph_edges"],
    )


@router.post("/analyze", response_model=AnalysisResult)
def analyze(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Trigger full analysis on an investigation."""
    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    result = _run_and_store_analysis(investigation_id, db)
    log_action(
        action="analysis_run",
        investigation_id=investigation_id,
        details={"findings": result["counts"]["findings"], "events": result["counts"]["total_events"]},
    )
    return AnalysisResult(
        message="Analysis complete.",
        investigation_id=investigation_id,
        findings_count=result["counts"]["findings"],
        timeline_count=result["counts"]["timeline_entries"],
        relationships_count=result["counts"]["graph_edges"],
    )


def _run_and_store_analysis(investigation_id: int, db: Session):
    """Load events, run analysis, persist findings/timeline/relationships, store result."""
    events = _load_events_from_db(investigation_id, db)

    # Load precomputed relationships if they exist (from DB)
    rel_rows = db.execute(
        select(Relationship).where(Relationship.investigation_id == investigation_id)
    ).scalars().all()
    rels = []
    for r in rel_rows:
        rels.append({
            "source_node": r.source_node,
            "source_type": r.source_type,
            "target_node": r.target_node,
            "target_type": r.target_type,
            "relationship_type": r.relationship_type,
            "evidence_event_ids": safe_json_loads(r.evidence_event_ids, []),
        })

    result = run_analysis(events, relationships_from_db=rels)

    # Update investigation status
    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one()
    inv.status = "analyzed"
    inv.risk_level = result["risk_level"]
    inv.confidence = result["confidence"]["score"]
    db.commit()

    analysis_persistence.persist_analysis(db, investigation_id, result)
    analysis_store.save_analysis(investigation_id, result)
    return result


@router.get("/findings", response_model=list[FindingResponse])
def get_findings(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Return all findings for an investigation."""
    analysis = _get_analysis(investigation_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found. Run analysis first.")
    findings = []
    for f in analysis["findings"]:
        findings.append(FindingResponse(
            id=0,
            finding_id=f["finding_id"],
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            confidence=f["confidence"],
            related_event_ids=f.get("related_event_ids", []),
            reason=f["reason"],
            category=f.get("category", "unknown"),
        ))
    return findings


@router.get("/timeline", response_model=TimelineResponse)
def get_timeline(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Return the chronological attack timeline."""
    analysis = _get_analysis(investigation_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found. Run analysis first.")
    entries = []
    for t in analysis["timeline"]:
        details = t.get("details")
        entries.append(TimelineEntrySchema(
            event_id=t["event_id"],
            timestamp=t["timestamp"],
            display_text=t["display_text"],
            sequence_order=t["sequence_order"],
            severity=t["severity"],
            details=details,
        ))
    return TimelineResponse(entries=entries, total_count=len(entries))


@router.get("/relationships", response_model=RelationshipGraphResponse)
def get_relationships(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Return the evidence relationship graph."""
    analysis = _get_analysis(investigation_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found. Run analysis first.")
    graph = analysis["graph"]

    # Convert edge evidence_event_ids to API-safe format
    edges = []
    for e in graph["edges"]:
        edges.append({
            "id": e["id"],
            "source": e["source"],
            "target": e["target"],
            "label": e["label"],
            "evidence_event_ids": e.get("evidence_event_ids", []),
            "inferred": e.get("inferred", False),
            "reason": e.get("reason"),
        })
    nodes = []
    for n in graph["nodes"]:
        nodes.append({
            "id": n["id"],
            "type": n["type"],
            "label": n["label"],
            "color": n["color"],
            "data": n.get("data", {}),
        })
    return RelationshipGraphResponse(nodes=nodes, edges=edges)


@router.get("/investigation", response_model=dict)
def get_investigation_analysis(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Return the full analysis summary for the dashboard."""
    analysis = _get_analysis(investigation_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found. Run analysis first.")
    return {
        "entry_point": analysis["entry_point"],
        "blast_radius": analysis["blast_radius"],
        "confidence": analysis["confidence"],
        "risk_level": analysis["risk_level"],
        "counts": analysis["counts"],
        "story": analysis["story"],
    }


@router.get("/correlations", response_model=list)
def get_correlations(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Return correlation pairs."""
    analysis = _get_analysis(investigation_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found. Run analysis first.")
    return analysis["correlations"][:500]


@router.get("/report", response_model=ReportData)
def get_report(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Return the structured investigation report data."""
    events = _load_events_from_db(investigation_id, db)
    analysis = _get_analysis(investigation_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found. Run analysis first.")

    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one()

    evidence_files = db.execute(
        select(EvidenceFile).where(EvidenceFile.investigation_id == investigation_id)
    ).scalars().all()

    summary = {
        "id": inv.id,
        "name": inv.name,
        "scenario_type": inv.scenario_type,
        "status": inv.status,
        "risk_level": inv.risk_level,
        "confidence": inv.confidence,
        "total_events": len(events),
        "suspicious_events": analysis["counts"]["suspicious_events"],
        "affected_users": analysis["blast_radius"].get("users", []),
        "affected_ips": analysis["blast_radius"].get("ips", []),
        "affected_hosts": analysis["blast_radius"].get("hosts", []),
        "affected_files": analysis["blast_radius"].get("files", []),
        "total_findings": len(analysis["findings"]),
        "created_at": str(inv.created_at),
    }

    findings = [
        FindingResponse(
            id=0,
            finding_id=f["finding_id"],
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            confidence=f["confidence"],
            related_event_ids=f.get("related_event_ids", []),
            reason=f["reason"],
            category=f.get("category", "unknown"),
        )
        for f in analysis["findings"]
    ]

    timeline = [
        TimelineEntrySchema(
            event_id=t["event_id"],
            timestamp=t["timestamp"],
            display_text=t["display_text"],
            sequence_order=t["sequence_order"],
            severity=t["severity"],
            details=t.get("details"),
        )
        for t in analysis["timeline"]
    ]

    br = analysis["blast_radius"]
    blast = BlastRadius(
        users=br.get("users", []),
        ips=br.get("ips", []),
        hosts=br.get("hosts", []),
        files=br.get("files", []),
        total_affected=br.get("total_affected", 0),
    )

    story = analysis["story"]
    conf = analysis["confidence"]
    attack_story = AttackStoryResponse(
        narrative=story["narrative"],
        key_findings=story["key_findings"],
        limitations=story["limitations"],
        confidence=ConfidenceDetail(
            score=conf["score"],
            factors=conf["factors"],
            level=conf["level"],
        ),
    )

    graph = analysis["graph"]
    rel_graph = RelationshipGraphResponse(
        nodes=graph["nodes"],
        edges=graph["edges"],
    )

    return ReportData(
        investigation=summary,
        findings=findings,
        timeline=timeline,
        blast_radius=blast,
        attack_story=attack_story,
        relationships=rel_graph,
        evidence_files=[{
            "filename": ef.filename,
            "category": ef.category,
            "event_count": ef.event_count,
            "sha256_hash": ef.sha256_hash,
            "message": f"Uploaded {ef.uploaded_at}",
        } for ef in evidence_files],
    )


@router.get("/report/html", response_class=HTMLResponse)
def get_report_html(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Return the print-friendly HTML report for direct download/printing."""
    report = get_report(investigation_id, db)
    analysis = _get_analysis(investigation_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found. Run analysis first.")

    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one()

    html = generate_report_html(
        investigation={
            "id": inv.id,
            "name": inv.name,
            "risk_level": inv.risk_level,
        },
        findings=[f.model_dump() for f in report.findings],
        timeline=[t.model_dump() for t in report.timeline],
        blast_radius=report.blast_radius.model_dump(),
        story={
            "narrative": report.attack_story.narrative,
            "limitations": report.attack_story.limitations,
        },
        graph=report.relationships.model_dump(),
        evidence_files=[f.model_dump() for f in report.evidence_files],
        confidence=report.attack_story.confidence.model_dump(),
        entry_point=analysis.get("entry_point"),
    )
    log_action(
        action="report_export",
        investigation_id=investigation_id,
        details={"format": "html"},
    )
    return HTMLResponse(content=html)