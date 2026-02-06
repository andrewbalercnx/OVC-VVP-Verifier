"""Database session management for VVP Issuer.

This module provides SQLAlchemy engine and session management:
- engine: The SQLAlchemy engine connected to the database
- SessionLocal: Session factory for creating database sessions
- get_db(): FastAPI dependency for request-scoped sessions
- get_db_session(): Context manager for non-request code
"""

import logging
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config import DATABASE_URL

log = logging.getLogger(__name__)

# Create engine with SQLite-specific settings
# For SQLite, we need check_same_thread=False for multi-threaded access
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,  # Set to True for SQL debugging
    pool_pre_ping=True,  # Verify connections before use
)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# Enable SQLite foreign key enforcement
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key enforcement for SQLite."""
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for database sessions.

    Usage:
        @app.get("/endpoint")
        def endpoint(db: Session = Depends(get_db)):
            ...

    The session is automatically closed when the request completes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context manager for database sessions in non-request code.

    Usage:
        with get_db_session() as db:
            org = db.query(Organization).filter(...).first()
            ...

    The session is committed on success and rolled back on exception.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_database() -> None:
    """Initialize the database by creating all tables.

    This is called during application startup in the lifespan handler.
    """
    from pathlib import Path
    from app.db.models import Base

    log.info(f"Initializing database at {DATABASE_URL}")

    # Ensure the database directory exists for SQLite
    if DATABASE_URL.startswith("sqlite:///"):
        db_path = DATABASE_URL.replace("sqlite:///", "")
        if db_path and db_path != ":memory:":
            db_dir = Path(db_path).parent
            db_dir.mkdir(parents=True, exist_ok=True)
            log.info(f"Ensured database directory exists: {db_dir}")

    Base.metadata.create_all(bind=engine)
    log.info("Database tables created successfully")
