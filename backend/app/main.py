"""
FastAPI application entry point for the Digital Forensics
Attack Story Reconstruction System.
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.models import init_db
from app.routes import evidence, events, investigations, analysis, audit, export, progress

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Initialize the database on app startup (at runtime, not import time).
    # DATABASE_URL / TRACELINE_DATABASE_URL are honored when set (Postgres on
    # serverless hosts like Vercel); otherwise a local SQLite file is used.
    init_db()
    yield


app = FastAPI(
    title="Digital Forensics Attack Story Reconstruction System",
    description="Correlates forensic evidence, detects suspicious activity, reconstructs "
                "attack timelines, and generates human-readable attack stories.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for the frontend. Local dev uses the Vite server on :5173.
# For cloud/Docker/Replit deploys, override via TRACELINE_ALLOWED_ORIGINS
# (comma-separated). Defaults cover local dev and the deployed Render UI host.
_allowed_origins_raw = os.environ.get("TRACELINE_ALLOWED_ORIGINS", "")
_allowed_origins = (
    [o.strip() for o in _allowed_origins_raw.split(",") if o.strip()]
    if _allowed_origins_raw
    else [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://traceline-ui.onrender.com",
        "https://traceline-ui.onrender.com/",
    ]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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