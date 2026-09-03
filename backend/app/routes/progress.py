"""
Pipeline Progress Streaming (SSE)
=================================
Exposes the analysis pipeline as a Server-Sent Events stream so the frontend
can show live progress (pipeline monitor) while an investigation is analyzed.

Each SSE event carries:
  - stage:     logical stage name (correlation, detection, entry_point, ...)
  - label:     human-readable stage label
  - percent:   cumulative 0-100 completion estimate
  - payload:   stage-specific detail (counts, ids, etc.)

Compliance: FR-14 (real-time pipeline progress + monitoring).
"""

import json
import queue
import threading
import time
from typing import Generator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dependencies import get_db, get_session
from app.models import Event, Investigation
from app.services.analysis_persistence import load_events_from_db
from app.analysis.engine import run_analysis

router = APIRouter(prefix="/api", tags=["analysis"])

# Stage ordering & weights for cumulative percent computation.
_STAGE_SEQUENCE = [
    ("started", "Initializing pipeline", 0),
    ("correlation", "Correlating events", 15),
    ("detection", "Detecting suspicious activity", 30),
    ("entry_point", "Locating initial entry point", 40),
    ("graph", "Tracing attack path", 55),
    ("blast_radius", "Calculating blast radius", 70),
    ("timeline", "Building timeline", 80),
    ("confidence", "Scoring confidence", 88),
    ("story", "Generating attack story", 95),
    ("done", "Analysis complete", 100),
]
_STAGE_PERCENT = {name: pct for name, _, pct in _STAGE_SEQUENCE}
_STAGE_LABEL = {name: label for name, label, _ in _STAGE_SEQUENCE}

_END = object()


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


@router.get("/analysis/progress")
def stream_analysis_progress(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    """Stream real-time pipeline progress for an investigation (SSE)."""
    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    q: "queue.Queue" = queue.Queue()

    def worker():
        session = get_session()
        try:
            # For fresh scenario loads the events are staged by the /load POST
            # *after* the investigation is created, so wait (poll) until they
            # are available before running the pipeline (FR-14 live progress).
            events = []
            for _ in range(60):
                if load_events_from_db(session, investigation_id):
                    break
                time.sleep(0.5)
            events = load_events_from_db(session, investigation_id)
            if not events:
                q.put({"event": "error", "stage": "error", "label": "No events available", "percent": 0,
                       "payload": {"detail": f"No events found for investigation {investigation_id}"}})
                return

            def on_stage(stage: str, payload: dict):
                q.put({
                    "event": "progress",
                    "stage": stage,
                    "label": _STAGE_LABEL.get(stage, stage),
                    "percent": _STAGE_PERCENT.get(stage, 0),
                    "payload": payload,
                })

            run_analysis(events, on_stage=on_stage)
        except Exception as exc:  # noqa: BLE001 - surface as an SSE error event
            q.put({"event": "error", "stage": "error", "label": "Analysis failed", "percent": 0,
                   "payload": {"detail": str(exc)}})
        finally:
            session.close()
            q.put(_END)

    def event_stream() -> Generator[str, None, None]:
        yield _sse({"event": "open", "stage": "open", "label": "Connected", "percent": 0,
                    "payload": {"investigation_id": investigation_id}})
        worker_thread = threading.Thread(target=worker, daemon=True)
        worker_thread.start()
        while True:
            item = q.get()
            if item is _END:
                break
            yield _sse(item)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
