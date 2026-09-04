from datetime import datetime, timezone
import os
from typing import Optional

from sqlalchemy import (
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase


class Base(DeclarativeBase):
    pass


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scenario_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)
    risk_level: Mapped[str] = mapped_column(String(50), default="UNKNOWN", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class EvidenceFile(Base):
    __tablename__ = "evidence_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        # Indexes required by FR-03.1 for rapid filtering/time-range queries.
        # SQLite can only sort a subset of index key types via the default
        # implementations used by the ORM, so we use "timestamp" (BLOB-safe
        # string) and composite columns.  Custom index types (datetime) are
        # deliberately avoided to keep the schema portable across SQLite/PG.
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_actor_timestamp", "user", "timestamp"),
        Index("ix_events_target_timestamp", "file_path", "timestamp"),
        Index("ix_events_investigation", "investigation_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    event_id: Mapped[str] = mapped_column(String(50), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(50), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    source_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    destination_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity: Mapped[str] = mapped_column(String(50), default="INFO", nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Forensic provenance: immutable pointer to the exact source file hash and
    # the 1-based logical line/record index from which this event was derived.
    raw_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    finding_id: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    related_event_ids: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)


class Correlation(Base):
    __tablename__ = "correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    event_a_event_id: Mapped[str] = mapped_column(String(50), nullable=False)
    event_b_event_id: Mapped[str] = mapped_column(String(50), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    factors: Mapped[str] = mapped_column(Text, nullable=False)


class TimelineEntry(Base):
    __tablename__ = "timeline_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    event_id: Mapped[str] = mapped_column(String(50), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(50), nullable=False)
    display_text: Mapped[str] = mapped_column(String(1024), nullable=False)
    sequence_order: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)


class Relationship(Base):
    __tablename__ = "relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    source_node: Mapped[str] = mapped_column(String(255), nullable=False)
    target_node: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_event_ids: Mapped[str] = mapped_column(Text, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    investigation_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


_engine = None


def _resolve_database_url(explicit: Optional[str] = None) -> str:
    """Return the effective database URL.

    Precedence: an explicitly passed URL > DATABASE_URL / TRACELINE_DATABASE_URL
    env vars > SQLite default. This lets the app run against Postgres on
    serverless hosts (Vercel) where only the env var is available, while
    keeping a local SQLite fallback for development/tests.
    """
    if explicit:
        return explicit
    env_url = os.environ.get("DATABASE_URL") or os.environ.get("TRACELINE_DATABASE_URL")
    return env_url or "sqlite:///traceline.db"


def get_engine(database_url: Optional[str] = None):
    global _engine
    if _engine is None:
        # Normalize Windows backslash paths for SQLAlchemy
        url = _resolve_database_url(database_url)
        url = url.replace("\\", "/") if url.startswith("sqlite:///") else url
        _engine = create_engine(url, echo=False, pool_pre_ping=True)

        if url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def _set_sqlite_pragma(dbapi_connection, _connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

    return _engine


def reset_engine() -> None:
    """Drop the cached engine (used by tests to switch DB backends)."""
    global _engine
    if _engine is not None:
        _engine.dispose()
        _engine = None


def init_db(database_url: Optional[str] = None):
    engine = get_engine(database_url)
    Base.metadata.create_all(engine)
    return engine
