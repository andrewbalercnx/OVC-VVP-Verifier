"""Sprint 67: Add org_type column and trust-anchor org_id fields.

Adds:
- organizations.org_type (VARCHAR(20), NOT NULL, default 'regular')
- mock_vlei_state.gleif_org_id (VARCHAR(36), nullable)
- mock_vlei_state.qvi_org_id (VARCHAR(36), nullable)
- mock_vlei_state.gsma_org_id (VARCHAR(36), nullable)

This migration is idempotent — safe to run multiple times.
"""

import logging
from sqlalchemy import text
from sqlalchemy.engine import Engine

log = logging.getLogger(__name__)


def _get_sqlite_columns(engine: Engine, table_name: str) -> set[str]:
    """Get column names for a SQLite table."""
    with engine.connect() as conn:
        result = conn.execute(text(f"PRAGMA table_info({table_name})"))
        return {row[1] for row in result}


def _run_postgresql(engine: Engine) -> None:
    """Run migration for PostgreSQL."""
    migration_sql = text("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'organizations'
                AND column_name = 'org_type'
            ) THEN
                ALTER TABLE organizations
                ADD COLUMN org_type VARCHAR(20) NOT NULL DEFAULT 'regular';
            END IF;
        END $$;

        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'mock_vlei_state'
                AND column_name = 'gleif_org_id'
            ) THEN
                ALTER TABLE mock_vlei_state ADD COLUMN gleif_org_id VARCHAR(36);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'mock_vlei_state'
                AND column_name = 'qvi_org_id'
            ) THEN
                ALTER TABLE mock_vlei_state ADD COLUMN qvi_org_id VARCHAR(36);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'mock_vlei_state'
                AND column_name = 'gsma_org_id'
            ) THEN
                ALTER TABLE mock_vlei_state ADD COLUMN gsma_org_id VARCHAR(36);
            END IF;
        END $$;
    """)
    with engine.connect() as conn:
        conn.execute(migration_sql)
        conn.commit()
    log.info("Sprint 67 PostgreSQL migration complete")


def _run_sqlite(engine: Engine) -> None:
    """Run migration for SQLite (existing databases only)."""
    with engine.connect() as conn:
        # Check if organizations table exists (fresh DB handled by create_all)
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='organizations'")
        )
        if result.fetchone() is None:
            log.debug("Sprint 67 SQLite migration skipped: tables not yet created")
            return

        # Add org_type column if missing
        org_cols = _get_sqlite_columns(engine, "organizations")
        if "org_type" not in org_cols:
            conn.execute(text(
                "ALTER TABLE organizations ADD COLUMN org_type VARCHAR(20) NOT NULL DEFAULT 'regular'"
            ))
            log.info("Added organizations.org_type column")

        # Check mock_vlei_state table exists
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='mock_vlei_state'")
        )
        if result.fetchone() is not None:
            state_cols = _get_sqlite_columns(engine, "mock_vlei_state")
            for col_name in ("gleif_org_id", "qvi_org_id", "gsma_org_id"):
                if col_name not in state_cols:
                    conn.execute(text(
                        f"ALTER TABLE mock_vlei_state ADD COLUMN {col_name} VARCHAR(36)"
                    ))
                    log.info(f"Added mock_vlei_state.{col_name} column")

        conn.commit()
    log.info("Sprint 67 SQLite migration complete")


def run_migrations(engine: Engine) -> None:
    """Run Sprint 67 migrations.

    Detects database dialect and runs the appropriate migration.
    Safe to call multiple times (idempotent).

    Args:
        engine: SQLAlchemy engine instance
    """
    backend = engine.url.get_backend_name()
    log.info(f"Running Sprint 67 migration (dialect: {backend})")

    if backend == "postgresql":
        _run_postgresql(engine)
    elif backend == "sqlite":
        _run_sqlite(engine)
    else:
        log.warning(f"Sprint 67 migration: unsupported dialect {backend}, skipping")
