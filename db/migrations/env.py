"""
Alembic migration environment — async-compatible configuration.

Supports both:
  - Online mode (run_migrations_online): applies migrations to a live DB
  - Offline mode (run_migrations_offline): generates SQL scripts without a DB connection

Uses asyncio + asyncpg for async DB access, matching the application's
SQLAlchemy setup.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Import Base and ALL models so Alembic autogenerate sees every table
from models import Base  # noqa: F401 — registers all models on Base.metadata
from models.api_key import APIKey  # noqa: F401
from models.application import Application  # noqa: F401
from models.audit_record import AuditRecord  # noqa: F401
from models.calibration_config import CalibrationConfig  # noqa: F401
from models.calibration_stats import CalibrationStats  # noqa: F401
from models.consent_version import ConsentVersion  # noqa: F401
from models.decision import Decision  # noqa: F401
from models.guideline_version import GuidelineVersion  # noqa: F401
from models.notification_outbox import NotificationOutbox  # noqa: F401
from models.retention_event import RetentionEvent  # noqa: F401
from models.reviewer import Reviewer, ReviewerFeedback  # noqa: F401

# Alembic Config object
config = context.config

# Configure Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata for autogenerate
target_metadata = Base.metadata

# Override sqlalchemy.url from environment variable
# This allows using the same alembic.ini across environments
dsn = os.environ.get("POSTGRES_DSN", "")
if dsn:
    # Convert asyncpg DSN to sync psycopg2 DSN for Alembic
    # (Alembic itself uses sync connections for migrations)
    sync_dsn = dsn.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
    config.set_main_option("sqlalchemy.url", sync_dsn)


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode — generates SQL without a DB connection.

    Useful for generating SQL scripts to review before applying,
    or for environments where direct DB access is not available during deploy.

    Usage: alembic upgrade head --sql > migration.sql
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Include schema-level changes in autogenerate
        include_schemas=True,
        # Compare server defaults (important for our text() defaults)
        compare_server_default=True,
        # Compare column types exactly
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Execute migrations within a connection context."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=True,
        compare_server_default=True,
        compare_type=True,
        # Render AS UUID for PostgreSQL UUID columns
        render_as_batch=False,
        # Transaction per migration for safer rollback
        transaction_per_migration=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in async mode using asyncpg-compatible engine."""
    # Use asyncpg for the migration connection to match app configuration
    async_dsn = os.environ.get("POSTGRES_DSN", config.get_main_option("sqlalchemy.url", ""))
    if not async_dsn.startswith("postgresql+asyncpg://"):
        # Convert sync DSN back to async if needed
        async_dsn = async_dsn.replace("postgresql+psycopg2://", "postgresql+asyncpg://")
        async_dsn = async_dsn.replace("postgresql://", "postgresql+asyncpg://")

    connectable = async_engine_from_config(
        {"sqlalchemy.url": async_dsn},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # No pooling for migration connections
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode — connects to DB and applies migrations."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()