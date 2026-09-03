#!/usr/bin/env bash
# Replit start script: install deps, build the SPA, then run the API that
# also serves the built frontend from the same origin (single web service).
set -e

echo ">>> Installing backend dependencies..."
pip install --quiet --upgrade -r backend/requirements.txt

echo ">>> Building frontend SPA..."
cd frontend
npm ci --silent
npm run build
cd ..

echo ">>> Starting uvicorn on port ${PORT:-8000}..."
cd backend
export TRACELINE_SERVE_FRONTEND=1
# Replit injects $PORT; fall back to 8000 otherwise.
uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
