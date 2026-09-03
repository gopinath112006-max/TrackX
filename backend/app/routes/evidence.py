"""Evidence upload & retrieval endpoints."""
from typing import List

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import EvidenceFile, Investigation, Event
from app.schemas.schemas import EvidenceUploadResponse
from app.services.evidence_parser import (
    detect_category,
    parse_evidence,
)
from app.services.normalizer import normalize_events
from app.services.audit_logger import log_action
from app.utils.helpers import sha256_file

router = APIRouter(prefix="/api", tags=["evidence"])

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {".csv", ".json", ".txt"}


def _category_from_param(category: str) -> str:
    """Map user-selected category to an internal category label."""
    cat_map = {
        "login": "login",
        "auth": "login",
        "authentication": "login",
        "file": "file_access",
        "file_access": "file_access",
        "network": "network",
        "system": "system",
        "database": "database",
    }
    return cat_map.get(category.lower(), "system")


@router.post("/evidence/upload", response_model=EvidenceUploadResponse)
async def upload_evidence(
    investigation_id: int = Form(...),
    file: UploadFile = File(...),
    category: str = Form("auto"),
    db: Session = Depends(get_db),
):
    """
    Upload an evidence file, validate it, parse it, normalize the events,
    and store them under the given investigation.

    Forensic safeguards:
      - file size limit (10 MB)
      - allowed extensions only
      - raw bytes are hashed with SHA-256 (never modified)
      - parsed events are normalized copies; original raw_text is preserved
    """
    # Validate file extension
    filename = file.filename or ""
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if f".{ext}" not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '.{ext}'. Allowed: csv, json, txt")

    # Validate investigation exists
    investigation = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one_or_none()
    if investigation is None:
        raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")

    # Read and size-limit the upload
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 10 MB size limit")

    file_hash = sha256_file(content)

    # Parse & normalize
    try:
        raw_events = parse_evidence(content, filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not raw_events:
        raise HTTPException(status_code=400, detail="No events could be extracted from the file")

    # Normalize raw events into the canonical structure (original raw_data preserved)
    normalized = normalize_events(raw_events, source=filename)
    raw_events = [ev.model_dump() for ev in normalized]

    resolved_category = _category_from_param(category)
    if category == "auto":
        resolved_category = detect_category(filename)

    # Persist evidence file record
    ev_file = EvidenceFile(
        investigation_id=investigation_id,
        filename=filename,
        category=resolved_category,
        sha256_hash=file_hash,
        event_count=len(raw_events),
    )
    db.add(ev_file)
    db.flush()  # get ev_file.id

    # Persist normalized events
    existing = db.execute(
        select(Event.event_id).where(Event.investigation_id == investigation_id)
    ).scalars().all()
    max_id = 0
    for eid in existing:
        try:
            num = int(eid.split("-")[1])
            max_id = max(max_id, num)
        except (IndexError, ValueError):
            continue

    for i, ev in enumerate(raw_events):
        # Force sequential event IDs for the investigation to avoid collisions
        new_id = f"EVT-{max_id + i + 1:04d}"
        ev["event_id"] = new_id
        from app.utils.helpers import safe_json_dumps

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
            raw_ref=safe_json_dumps(ev.get("raw_ref")),
            raw_data=safe_json_dumps(ev.get("raw_data")),
        ))

    db.commit()

    log_action(
        action="evidence_upload",
        investigation_id=investigation_id,
        details={"filename": filename, "event_count": len(raw_events), "sha256": file_hash},
    )

    return EvidenceUploadResponse(
        filename=filename,
        category=resolved_category,
        event_count=len(raw_events),
        sha256_hash=file_hash,
        message=f"{filename} imported successfully. {len(raw_events)} events detected.",
    )


@router.get("/evidence", response_model=List[EvidenceUploadResponse])
def list_evidence(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """List all uploaded evidence files for an investigation."""
    rows = db.execute(
        select(EvidenceFile).where(EvidenceFile.investigation_id == investigation_id)
    ).scalars().all()
    return [
        EvidenceUploadResponse(
            filename=r.filename,
            category=r.category,
            event_count=r.event_count,
            sha256_hash=r.sha256_hash,
            message=f"{r.filename} imported ({r.event_count} events) on {r.uploaded_at}",
        )
        for r in rows
    ]