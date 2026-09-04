"""Vercel serverless entrypoint for the FastAPI backend (dedicated project).

This is the battle-tested classic Vercel Python Function layout: a single
`api/index.py` function at the project root that exposes the ASGI app. The
`backend/` package is made importable by adding this directory's parent to
``sys.path``.
"""

import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app.main import app  # noqa: E402

__all__ = ["app"]
