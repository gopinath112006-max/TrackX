"""Top-level FastAPI entrypoint shim for Vercel Services.

Vercel's Python builder resolves the service entrypoint relative to the
service root (`backend/`). Using a top-level module here mirrors the official
`vite-fastapi` Services example and is reliably detected across builder
versions, unlike the nested `app.main` package module.
"""

from app.main import app

__all__ = ["app"]
