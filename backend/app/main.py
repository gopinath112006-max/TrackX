"""
FastAPI application entry point for the Digital Forensics
Attack Story Reconstruction System.
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.models import init_db
from app.routes import evidence, events, investigations, analysis, audit, export, progress

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(
    title="Digital Forensics Attack Story Reconstruction System",
    description="Correlates forensic evidence, detects suspicious activity, reconstructs "
                "attack timelines, and generates human-readable attack stories.",
    version="1.0.0",
)

# CORS for the frontend. Local dev uses the Vite server on :5173.
# For cloud/Docker deploys, override via TRACELINE_ALLOWED_ORIGINS (comma-separated).
_allowed_origins_raw = os.environ.get("TRACELINE_ALLOWED_ORIGINS", "")
_allowed_origins = (
    [o.strip() for o in _allowed_origins_raw.split(",") if o.strip()]
    if _allowed_origins_raw
    else ["http://localhost:5173", "http://127.0.0.1:5173"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the database on startup.
# Honor an explicit TRACELINE_DATABASE_URL (e.g. for Docker volume mounts /
# local Postgres, per NFR-D-01); otherwise default to backend/traceline.db.
_db_url = os.environ.get("TRACELINE_DATABASE_URL")
if not _db_url:
    _db_path = os.path.join(BASE_DIR, "..", "traceline.db").replace("\\", "/")
    _db_url = f"sqlite:///{_db_path}"
init_db(_db_url)


@app.get("/api/health", tags=["system"])
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "Digital Forensics Investigation API"}


app.include_router(evidence.router)
app.include_router(events.router)
app.include_router(investigations.router)
app.include_router(analysis.router)
app.include_router(audit.router)
app.include_router(export.router)
app.include_router(progress.router)

# Optional: serve the built frontend (frontend/dist) from the same origin.
# Turn on with TRACELINE_SERVE_FRONTEND=1 so a single host (e.g. Replit) can
# serve the SPA and /api together, without cross-origin CORS. Enabled only when
# a production build exists; ignored during local dev / Docker.
if os.environ.get("TRACELINE_SERVE_FRONTEND", "").strip() == "1":
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    _dist = os.path.normpath(os.path.join(BASE_DIR, "..", "..", "frontend", "dist"))
    if os.path.isdir(_dist):
        app.mount("/assets", StaticFiles(directory=os.path.join(_dist, "assets")), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa_fallback(full_path: str):
            candidate = os.path.normpath(os.path.join(_dist, full_path))
            if os.path.isfile(candidate):
                return FileResponse(candidate)
            return FileResponse(os.path.join(_dist, "index.html"))