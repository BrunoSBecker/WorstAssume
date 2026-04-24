"""
Shared pytest fixtures for WorstAssume tests.

Provides:
  - in_memory_db        : a fresh SQLAlchemy Session backed by :memory: SQLite
  - account_a / account_b : pre-created Account rows in an in-memory DB
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from worstassume.db.models import Base, Account


@pytest.fixture()
def db_session():
    """Return a fresh SQLAlchemy session backed by an in-memory SQLite DB."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def account_a(db_session):
    """A tracked account with ID 111111111111."""
    from worstassume.db.store import get_or_create_account
    acct = get_or_create_account(
        db_session,
        account_id="111111111111",
        account_name="Account-A",
    )
    db_session.commit()
    return acct


@pytest.fixture()
def account_b(db_session):
    """A second tracked account with ID 222222222222."""
    from worstassume.db.store import get_or_create_account
    acct = get_or_create_account(
        db_session,
        account_id="222222222222",
        account_name="Account-B",
    )
    db_session.commit()
    return acct
