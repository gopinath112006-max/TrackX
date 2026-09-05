"""Vercel serverless entrypoint for the FastAPI backend (dedicated project).

Vercel's classic Python Function runtime reliably serves a *WSGI* callable
exposed as ``handler``. FastAPI is ASGI, so we bridge it with ``a2wsgi``. The
``backend/`` package is made importable by adding this directory's parent to
``sys.path``.
"""

import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from a2wsgi import WSGIMiddleware  # noqa: E402
from app.main import app  # noqa: E402

handler = WSGIMiddleware(app)

app = handler  # also expose for local run via `vercel dev`
__all__ = ["handler", "app"]
