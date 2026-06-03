"""
ComplianceLoop — Async Database Session
=========================================
Provides the async SQLAlchemy session factory and FastAPI dependency.

Usage in FastAPI route handlers:
    from db.session import get_db

    @router.post("/applications")
    async def create_application(
        db: AsyncSession = Depends(get_db),
    ) -> ApplicationResponse:
        ...

Usage in Celery tasks (non-FastAPI context):
    from db.session import get_session_context

    async def my_task():
        async with get_session_context() as db:
            result = await db.execute(select(Application))
            ...

Demo mode:
    Pass is_demo=True to get a session on the demo database.
    In FastAPI, the is_demo flag is injected by the demo middleware.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from db.engine import get_engine_for_context

logger = logging.getLogger(__name__)

# Session factory singletons (one per engine)
_session_factory: async_sessionmaker[AsyncSession] | None = None
_demo_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_session_factory(is_demo: bool = False) -> async_sessionmaker[AsyncSession]:
    """
    Build a session factory for the given context.

    Session configuration:
      - autocommit=False: explicit transaction management
      - autoflush=False: manual flush control (important for audit pre-write ordering)
      - expire_on_commit=False: objects remain usable after commit
        (critical for Celery tasks that commit then use the result)
    """
    engine = get_engine_for_context(is_demo)
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )


def get_session_factory(is_demo: bool = False) -> async_sessionmaker[AsyncSession]:
    """Return the session factory singleton for the given context."""
    global _session_factory, _demo_session_factory  # noqa: PLW0603

    if is_demo:
        if _demo_session_factory is None:
            _demo_session_factory = _build_session_factory(is_demo=True)
        return _demo_session_factory

    if _session_factory is None:
        _session_factory = _build_session_factory(is_demo=False)
    return _session_factory


# ── FastAPI dependency ────────────────────────────────────────────────────────

async def get_db(
    is_demo: bool = False,
) -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an async database session.

    Handles commit/rollback automatically:
      - On success: commits the session
      - On exception: rolls back before re-raising

    Usage:
        @router.post("/applications")
        async def create(db: AsyncSession = Depends(get_db)):
            ...

    For demo mode, use get_demo_db dependency instead.
    """
    factory = get_session_factory(is_demo=is_demo)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_demo_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for demo database session.

    Use in demo-specific routes:
        @router.post("/demo/guidelines/edit")
        async def edit(db: AsyncSession = Depends(get_demo_db)):
            ...
    """
    async for session in get_db(is_demo=True):
        yield session


# ── Context manager for non-FastAPI use (Celery tasks) ───────────────────────

@asynccontextmanager
async def get_session_context(
    is_demo: bool = False,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for database sessions outside FastAPI.

    Used in Celery tasks, scripts, and tests that don't have
    FastAPI's dependency injection available.

    Usage:
        async with get_session_context() as db:
            result = await db.execute(select(Application))
            applications = result.scalars().all()

    Unlike get_db(), this does NOT auto-commit — caller must commit explicitly
    for Celery tasks to have precise control over transaction boundaries.
    """
    factory = get_session_factory(is_demo=is_demo)
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_autocommit_session_context(
    is_demo: bool = False,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager that auto-commits on successful exit.

    For use in Celery tasks that follow a simple write-and-done pattern.
    """
    factory = get_session_factory(is_demo=is_demo)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise