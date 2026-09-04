"""
Vercel serverless entrypoint for TraceLine.

Exports the FastAPI `app` so Vercel runs the whole backend as a single Python
function under the Python runtime. Vercel bundles the entire repository, so we
add the `backend/` directory to ``sys.path`` to make the existing `app.*`
absolute imports resolve unchanged.
"""

import os
import sys

_BACKEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app.main import app  # noqa: E402  (the FastAPI application)

__all__ = ["app"]
