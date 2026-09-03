# TraceLine API container (NFR-D-01 / NFR-D-02)
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source and externalized configuration.
COPY app ./app
COPY config ./config

# Persistent state lives on a dedicated volume mounted at /app/data.
# Defaults (overridable via TRACELINE_DATABASE_URL / TRACELINE_AUDIT_LOG).
ENV TRACELINE_DATABASE_URL=sqlite:////app/data/traceline.db \
    TRACELINE_AUDIT_LOG=/app/data/audit.log \
    TRACELINE_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:80

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
