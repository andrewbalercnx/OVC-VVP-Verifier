"""Sprint 61: Add vetter certification columns.

Adds:
- organizations.vetter_certification_said (VARCHAR(44), nullable)
- mock_vlei_state.gsma_aid (VARCHAR(44), nullable)
- mock_vlei_state.gsma_registry_key (VARCHAR(44), nullable)

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
                AND column_name = 'vetter_certification_said'
            ) THEN
                ALTER TABLE organizations
                ADD COLUMN vetter_certification_said VARCHAR(44);
            END IF;
        END $$;

        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'mock_vlei_state'
                AND column_name = 'gsma_aid'
            ) THEN
                ALTER TABLE mock_vlei_state ADD COLUMN gsma_aid VARCHAR(44);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'mock_vlei_state'
                AND column_name = 'gsma_registry_key'
            ) THEN
                ALTER TABLE mock_vlei_state
                ADD COLUMN gsma_registry_key VARCHAR(44);
            END IF;
        END $$;
    """)
    with engine.connect() as conn:
        conn.execute(migration_sql)
        conn.commit()
    log.info("Sprint 61 PostgreSQL migration complete")


def _run_sqlite(engine: Engine) -> None:
    """Run migration for SQLite (existing databases only)."""
    with engine.connect() as conn:
        # Check if organizations table exists (fresh DB handled by create_all)
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='organizations'")
        )
        if result.fetchone() is None:
            log.debug("Sprint 61 SQLite migration skipped: tables not yet created")
            return

        # Add columns if missing
        org_cols = _get_sqlite_columns(engine, "organizations")
        if "vetter_certification_said" not in org_cols:
            conn.execute(text(
                "ALTER TABLE organizations ADD COLUMN vetter_certification_said VARCHAR(44)"
            ))
            log.info("Added organizations.vetter_certification_said column")

        # Check mock_vlei_state table exists
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='mock_vlei_state'")
        )
        if result.fetchone() is not None:
            state_cols = _get_sqlite_columns(engine, "mock_vlei_state")
            if "gsma_aid" not in state_cols:
                conn.execute(text(
                    "ALTER TABLE mock_vlei_state ADD COLUMN gsma_aid VARCHAR(44)"
                ))
                log.info("Added mock_vlei_state.gsma_aid column")
            if "gsma_registry_key" not in state_cols:
                conn.execute(text(
                    "ALTER TABLE mock_vlei_state ADD COLUMN gsma_registry_key VARCHAR(44)"
                ))
                log.info("Added mock_vlei_state.gsma_registry_key column")

        conn.commit()
    log.info("Sprint 61 SQLite migration complete")


def run_migrations(engine: Engine) -> None:
    """Run Sprint 61 migrations.

    Detects database dialect and runs the appropriate migration.
    Safe to call multiple times (idempotent).

    Args:
        engine: SQLAlchemy engine instance
    """
    backend = engine.url.get_backend_name()
    log.info(f"Running Sprint 61 migration (dialect: {backend})")

    if backend == "postgresql":
        _run_postgresql(engine)
    elif backend == "sqlite":
        _run_sqlite(engine)
    else:
        log.warning(f"Sprint 61 migration: unsupported dialect {backend}, skipping")
