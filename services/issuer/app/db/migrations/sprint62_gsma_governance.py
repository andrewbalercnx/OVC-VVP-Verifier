"""Sprint 62: Add GSMA governance credential column.

Adds:
- mock_vlei_state.gsma_governance_said (VARCHAR(44), nullable)

This migration is idempotent — safe to run multiple times.
"""

import logging
from sqlalchemy import text
from sqlalchemy.engine import Engine

log = logging.getLogger(__name__)


def _run_postgresql(engine: Engine) -> None:
    """Run migration for PostgreSQL."""
    migration_sql = text("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'mock_vlei_state'
                AND column_name = 'gsma_governance_said'
            ) THEN
                ALTER TABLE mock_vlei_state
                ADD COLUMN gsma_governance_said VARCHAR(44);
            END IF;
        END $$;
    """)
    with engine.connect() as conn:
        conn.execute(migration_sql)
        conn.commit()
    log.info("Sprint 62 PostgreSQL migration complete")


def _run_sqlite(engine: Engine) -> None:
    """Run migration for SQLite (existing databases only)."""
    with engine.connect() as conn:
        # Check if mock_vlei_state table exists
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='mock_vlei_state'")
        )
        if result.fetchone() is None:
            log.debug("Sprint 62 SQLite migration skipped: table not yet created")
            return

        # Get existing columns
        result = conn.execute(text("PRAGMA table_info(mock_vlei_state)"))
        existing_cols = {row[1] for row in result}

        if "gsma_governance_said" not in existing_cols:
            conn.execute(text(
                "ALTER TABLE mock_vlei_state ADD COLUMN gsma_governance_said VARCHAR(44)"
            ))
            log.info("Added mock_vlei_state.gsma_governance_said column")

        conn.commit()
    log.info("Sprint 62 SQLite migration complete")


def run_migrations(engine: Engine) -> None:
    """Run Sprint 62 migrations.

    Detects database dialect and runs the appropriate migration.
    Safe to call multiple times (idempotent).
    """
    backend = engine.url.get_backend_name()
    log.info(f"Running Sprint 62 migration (dialect: {backend})")

    if backend == "postgresql":
        _run_postgresql(engine)
    elif backend == "sqlite":
        _run_sqlite(engine)
    else:
        log.warning(f"Sprint 62 migration: unsupported dialect {backend}, skipping")
