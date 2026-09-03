"""
Report / Export Routes
======================
FR-12.2: Downloadable publication-quality PDF report.
FR-12.3: Structured machine-readable ZIP export (events.csv, blast_radius.json,
         attack_path.json, findings.json, iocs.csv, incident_report.pdf).
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import EvidenceFile, Investigation
from app.services import analysis_persistence, analysis_store, audit_logger
from app.services.export_service import generate_export_zip, generate_pdf_report

router = APIRouter(prefix="/api", tags=["export"])


def _get_analysis(investigation_id: int, db: Session):
    analysis = analysis_store.get_analysis(investigation_id)
    if analysis is not None:
        return analysis
    return analysis_persistence.restore_analysis(db, investigation_id)


@router.get("/report/pdf")
def get_report_pdf(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Download the publication-quality PDF incident report (FR-12.2)."""
    analysis = _get_analysis(investigation_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found. Run analysis first.")

    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one()
    evidence_files = db.execute(
        select(EvidenceFile).where(EvidenceFile.investigation_id == investigation_id)
    ).scalars().all()

    report = _assemble_report(investigation_id, analysis, inv, evidence_files, db)

    pdf = generate_pdf_report(
        investigation=report["investigation"],
        findings=report["findings"],
        timeline=report["timeline"],
        blast_radius=report["blast_radius"],
        story=report["story"],
        graph=report["graph"],
        evidence_files=report["evidence_files"],
        confidence=report["confidence"],
        entry_point=analysis.get("entry_point"),
    )

    audit_logger.log_action(
        action="report_export",
        investigation_id=investigation_id,
        details={"format": "pdf"},
    )

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=TraceLine_Incident_Report_{investigation_id}.pdf"
        },
    )


@router.get("/export/zip")
def export_zip(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Download the machine-readable investigation export archive (FR-12.3)."""
    analysis = _get_analysis(investigation_id, db)
    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found. Run analysis first.")

    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one()
    evidence_files = db.execute(
        select(EvidenceFile).where(EvidenceFile.investigation_id == investigation_id)
    ).scalars().all()

    events = analysis_persistence.load_events_from_db(db, investigation_id)
    event_dicts = [e.model_dump() for e in events]
    report = _assemble_report(investigation_id, analysis, inv, evidence_files, db)

    zip_bytes = generate_export_zip(
        investigation=report["investigation"],
        events=event_dicts,
        blast_radius=report["blast_radius"],
        findings=report["findings"],
        attack_path=report["graph"],
        include_pdf=True,
    )

    audit_logger.log_action(
        action="export_zip",
        investigation_id=investigation_id,
        details={"files": ["events.csv", "blast_radius.json", "attack_path.json", "findings.json", "iocs.csv", "incident_report.pdf"]},
    )

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=TraceLine_Export_{investigation_id}.zip"
        },
    )


def _assemble_report(investigation_id, analysis, inv, evidence_files, db):
    """Assemble report sections from persisted analysis (kept simple/durable)."""
    br = analysis.get("blast_radius") or {}
    story = analysis.get("story") or {}
    confidence = analysis.get("confidence") or {"score": 0, "level": "LOW"}

    ev_files = [{
        "filename": ef.filename,
        "category": ef.category,
        "event_count": ef.event_count,
        "sha256_hash": ef.sha256_hash,
        "message": f"Uploaded {ef.uploaded_at}",
    } for ef in evidence_files]

    return {
        "investigation": {
            "id": inv.id,
            "name": inv.name,
            "risk_level": inv.risk_level,
            "total_events": analysis.get("counts", {}).get("total_events", 0),
            "evidence_files": ev_files,
            "entry_point": analysis.get("entry_point"),
            "confidence": confidence,
        },
        "findings": analysis.get("findings", []),
        "timeline": [],
        "blast_radius": br,
        "story": story,
        "graph": analysis.get("graph") or {"nodes": [], "edges": []},
        "evidence_files": ev_files,
        "confidence": confidence,
    }
