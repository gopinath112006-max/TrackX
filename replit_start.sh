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
  # More forgiving than `npm ci` on a fresh Replit environment.
  npm install --silent --no-audit --no-fund || npm ci --silent
  npm run build
  cd ..
else
  echo ">>> Frontend build already present (skipping)."
fi

# Ensure the uvicorn binary is on PATH (pip may install into a user/venv bin dir).
PY_BIN="$(python -c 'import sys, os; print(os.path.dirname(sys.executable))' 2>/dev/null || true)"
[ -n "$PY_BIN" ] && export PATH="$PY_BIN:$PATH"

PORT="${PORT:-8000}"
echo ">>> Starting uvicorn on port ${PORT}..."
cd backend
export TRACELINE_SERVE_FRONTEND=1
# Replit injects $PORT; fall back to 8000 otherwise.
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}"
