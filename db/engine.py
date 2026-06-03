"""
ComplianceLoop — Database Engine
===================================
Creates and configures the async SQLAlchemy engine.

Uses asyncpg driver (postgresql+asyncpg://) for full async support.
The engine is a singleton — created once per process and reused.

Pool configuration is tuned for NBFC workload:
  - pool_size=20: handles bursts of concurrent pipeline runs
  - max_overflow=10: allows up to 30 total connections under peak load
  - pool_timeout=30: fail fast rather than queue indefinitely
  - pool_pre_ping=True: validates connections before use (detects stale connections)
  - pool_recycle=3600: recycle connections every hour to avoid Postgres idle timeouts
"""

from __future__ import annotations

import logging
import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    create_async_engine,
)

logger = logging.getLogger(__name__)

# Module-level engine singletons
_engine: AsyncEngine | None = None
_demo_engine: AsyncEngine | None = None


def _build_engine(dsn: str, *, echo: bool = False) -> AsyncEngine:
    """
    Build a configured async SQLAlchemy engine for a given DSN.

    Args:
        dsn: PostgreSQL DSN in asyncpg format:
             postgresql+asyncpg://user:pass@host:port/dbname
        echo: If True, log all SQL statements (development only).

    Returns:
        Configured AsyncEngine instance.
    """
    return create_async_engine(
        dsn,
        # ── Connection pool ────────────────────────────────────────────────
        pool_size=int(os.environ.get("POSTGRES_POOL_SIZE", "20")),
        max_overflow=int(os.environ.get("POSTGRES_MAX_OVERFLOW", "10")),
        pool_timeout=int(os.environ.get("POSTGRES_POOL_TIMEOUT", "30")),
        pool_pre_ping=True,          # Validate connection before use
        pool_recycle=3600,           # Recycle connections every hour
        # ── Query execution ────────────────────────────────────────────────
        echo=echo,                   # Log SQL — set via POSTGRES_ECHO env var
        echo_pool=False,             # Pool debug logging — always off in prod
        # ── Connection args ────────────────────────────────────────────────
        connect_args={
            "command_timeout": 60,   # Statement timeout: 60 seconds
            "server_settings": {
                # Enforce UTC timezone for all connections
                "timezone": "UTC",
                # Application name visible in pg_stat_activity
                "application_name": "complianceloop",
                # Lock timeout: fail fast on lock contention (important for audit writes)
                "lock_timeout": "10s",
                # Statement timeout at connection level (belt-and-suspenders)
                "statement_timeout": "60s",
            },
        },
    )


def get_engine() -> AsyncEngine:
    """
    Return the production database engine singleton.
    Creates it on first call using POSTGRES_DSN environment variable.

    Raises:
        RuntimeError: If POSTGRES_DSN is not configured.
    """
    global _engine  # noqa: PLW0603
    if _engine is None:
        dsn = os.environ.get("POSTGRES_DSN", "")
        if not dsn:
            raise RuntimeError(
                "POSTGRES_DSN environment variable is not set. "
                "Example: postgresql+asyncpg://user:pass@localhost:5432/complianceloop"
            )
        echo = os.environ.get("POSTGRES_ECHO", "false").lower() == "true"
        _engine = _build_engine(dsn, echo=echo)
        logger.info("Production database engine created.")
    return _engine


def get_demo_engine() -> AsyncEngine:
    """
    Return the demo database engine singleton.
    Creates it on first call using DEMO_POSTGRES_DSN environment variable.

    The demo engine connects to a completely separate PostgreSQL database
    (different instance, different port) to ensure demo data and production
    data share no storage.

    Raises:
        RuntimeError: If DEMO_POSTGRES_DSN is not configured.
    """
    global _demo_engine  # noqa: PLW0603
    if _demo_engine is None:
        dsn = os.environ.get("DEMO_POSTGRES_DSN", "")
        if not dsn:
            raise RuntimeError(
                "DEMO_POSTGRES_DSN environment variable is not set. "
                "Required when DEMO_MODE=true."
            )
        _demo_engine = _build_engine(dsn, echo=False)
        logger.info("Demo database engine created.")
    return _demo_engine


def get_engine_for_context(is_demo: bool = False) -> AsyncEngine:
    """
    Return the correct engine based on demo context.

    Args:
        is_demo: If True, return the demo engine. Otherwise return prod engine.

    Returns:
        The appropriate AsyncEngine.
    """
    return get_demo_engine() if is_demo else get_engine()


async def dispose_engines() -> None:
    """
    Dispose all engine connection pools.
    Called during application shutdown to cleanly close all DB connections.
    """
    global _engine, _demo_engine  # noqa: PLW0603
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        logger.info("Production database engine disposed.")
    if _demo_engine is not None:
        await _demo_engine.dispose()
        _demo_engine = None
        logger.info("Demo database engine disposed.")


async def check_database_health(is_demo: bool = False) -> bool:
    """
    Check database connectivity by executing a trivial query.

    Used by the /health endpoint.

    Args:
        is_demo: If True, check demo database.

    Returns:
        True if database is reachable, False otherwise.
    """
    engine = get_engine_for_context(is_demo)
    try:
        async with engine.connect() as conn:
            from sqlalchemy import text  # noqa: PLC0415
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error("Database health check failed: %s", exc)
        return False