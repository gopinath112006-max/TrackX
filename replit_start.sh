#!/usr/bin/env bash
# Replit start script: install deps, build the SPA, then run the API that
# also serves the built frontend from the same origin (single web service).
set -e

# Skip re-installs / rebuilds when already present, so every-run startup is
# fast (deps persist in Replit's package cache across runs).
if ! python -c "import fastapi, uvicorn, sqlalchemy" 2>/dev/null; then
  echo ">>> Installing backend dependencies..."
  pip install --quiet --upgrade -r backend/requirements.txt
else
  echo ">>> Backend dependencies already installed (skipping)."
fi

if [ ! -f frontend/dist/index.html ]; then
  echo ">>> Building frontend SPA..."
  cd frontend
  npm ci --silent
  npm run build
  cd ..
else
  echo ">>> Frontend build already present (skipping)."
fi

echo ">>> Starting uvicorn on port ${PORT:-8000}..."
cd backend
export TRACELINE_SERVE_FRONTEND=1
# Replit injects $PORT; fall back to 8000 otherwise.
uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
