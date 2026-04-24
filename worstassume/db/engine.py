"""Database engine initialization — creates SQLite DB at ~/.worst/worst.db by default."""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import sessionmaker, Session

from worstassume.db.models import Base

_DEFAULT_DB_PATH = Path.home() / ".worst" / "worst.db"

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def init_db(path: str | Path | None = None) -> Engine:
    """Initialize the SQLite database, creating tables if they don't exist."""
    global _engine, _SessionLocal

    db_path = Path(path) if path else Path(os.environ.get("WORST_DB", str(_DEFAULT_DB_PATH)))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    url = f"sqlite:///{db_path}"
    _engine = create_engine(url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)

    return _engine


def get_session() -> Session:
    """Return a new SQLAlchemy session. Caller is responsible for closing it."""
    if _SessionLocal is None:
        init_db()
    return _SessionLocal()


def get_db_path() -> Path:
    return Path(os.environ.get("WORST_DB", str(_DEFAULT_DB_PATH)))
