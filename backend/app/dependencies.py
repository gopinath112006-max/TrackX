"""Dependencies: shared FastAPI dependencies for DB session and state."""
from typing import Generator

from fastapi import Depends
from sqlalchemy.orm import Session

from app.models import get_engine


def get_db() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy session bound to the shared engine."""
    engine = get_engine()
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()


def get_session() -> Session:
    """Return a new session directly (for use in non-request code)."""
    return Session(get_engine())