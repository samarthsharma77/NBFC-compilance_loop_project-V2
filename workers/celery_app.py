"""
ComplianceLoop — Celery Application Factory
=============================================
Creates and configures the Celery application instance.

This module is the entry point for all Celery operations:
  - celery -A workers.celery_app worker  (pipeline + retro_eval + notifications)
  - celery -A workers.celery_app beat    (scheduler)
  - celery -A workers.celery_app flower  (monitoring UI)

Configuration strategy:
  All config values come from environment variables (loaded via secrets_loader
  at worker startup). No hardcoded values except safe non-secret defaults.

Task autodiscovery:
  Celery discovers tasks from all registered app modules. Each module
  that contains @app.task decorated functions is listed in CELERY_IMPORTS.

Signal handlers:
  - worker_init: loads secrets, configures logging, initialises observability
  - worker_ready: logs worker startup with queue assignments
  - task_prerun: binds correlation context for structured logging
  - task_postrun: clears context, records metrics
  - task_failure: records error metrics, logs with full context
  - task_retry: logs retry attempt with backoff info
"""

from __future__ import annotations

import logging
import os
from typing import Any

from celery import Celery
from celery.signals import (
    task_failure,
    task_postrun,
    task_prerun,
    task_retry,
    worker_init,
    worker_ready,
    worker_shutdown,
)

from workers.queues import ALL_QUEUES, TASK_ROUTES

logger = logging.getLogger(__name__)

# ── Application factory ───────────────────────────────────────────────────────

def create_celery_app() -> Celery:
    """
    Create and configure the ComplianceLoop Celery application.

    Returns:
        Configured Celery instance.
    """
    app = Celery("complianceloop")

    # ── Broker + result backend ───────────────────────────────────────────────
    broker_url = os.environ.get(
        "CELERY_BROKER_URL",
        "redis://:changeme@localhost:6379/2",
    )
    result_backend = os.environ.get(
        "CELERY_RESULT_BACKEND",
        "redis://:changeme@localhost:6379/3",
    )

    # ── Core configuration ────────────────────────────────────────────────────
    app.conf.update(
        # ── Connection ──────────────────────────────────────────────────────
        broker_url=broker_url,
        result_backend=result_backend,
        broker_connection_retry_on_startup=True,
        broker_connection_retry=True,
        broker_connection_max_retries=10,

        # ── Serialisation ────────────────────────────────────────────────────
        # JSON only — never pickle (security: pickle allows arbitrary code exec)
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        event_serializer="json",

        # ── Queues ───────────────────────────────────────────────────────────
        task_queues=ALL_QUEUES,
        task_routes=TASK_ROUTES,
        task_default_queue="pipeline",
        task_default_exchange="complianceloop",
        task_default_routing_key="pipeline",

        # ── Task execution ───────────────────────────────────────────────────
        task_always_eager=False,            # Never run tasks inline (use queue)
        task_eager_propagates=True,         # Propagate exceptions in eager mode (tests)
        task_acks_late=True,                # ACK after task completes, not before
                                            # (ensures task is re-queued if worker crashes)
        task_reject_on_worker_lost=True,    # Re-queue if worker dies mid-task
        worker_prefetch_multiplier=1,       # Fetch one task at a time per worker
                                            # (prevents one slow task starving fast ones)

        # ── Timeouts ────────────────────────────────────────────────────────
        task_soft_time_limit=int(os.environ.get("CELERY_TASK_SOFT_TIME_LIMIT", "120")),
        task_time_limit=int(os.environ.get("CELERY_TASK_TIME_LIMIT", "180")),

        # ── Retries ──────────────────────────────────────────────────────────
        task_max_retries=int(os.environ.get("CELERY_TASK_MAX_RETRIES", "3")),

        # ── Result storage ───────────────────────────────────────────────────
        result_expires=3600,                # Results expire after 1 hour
        result_persistent=True,             # Persist results across broker restarts

        # ── Task tracking ────────────────────────────────────────────────────
        task_track_started=True,            # Mark tasks as STARTED (visible in Flower)
        task_send_sent_event=True,          # Emit task-sent events for monitoring

        # ── Worker configuration ─────────────────────────────────────────────
        worker_concurrency=int(os.environ.get("CELERY_WORKER_CONCURRENCY", "4")),
        worker_max_tasks_per_child=1000,    # Restart worker process after 1000 tasks
                                            # (prevents memory leaks from LLM inference)
        worker_disable_rate_limits=False,   # Keep rate limits active

        # ── Beat scheduler ────────────────────────────────────────────────────
        beat_scheduler="celery.beat:PersistentScheduler",
        beat_schedule_filename="/tmp/celerybeat-schedule",

        # ── Timezone ─────────────────────────────────────────────────────────
        timezone="UTC",
        enable_utc=True,

        # ── Task autodiscovery ────────────────────────────────────────────────
        # Explicitly list task modules — more reliable than autodiscover_tasks
        # in containerised environments where package structure may vary
        imports=[
            "workers.notification_worker",
            # These will be added as phases are completed:
            # "pipeline.tasks",
            # "retro_eval.tasks",
            # "scraper.tasks",
            # "calibration.tasks",
            # "dpdp.retention_enforcer",
            # "audit.s3_uploader",
        ],

        # ── Logging ──────────────────────────────────────────────────────────
        # Disable Celery's default logging hijack — we manage logging via structlog
        worker_hijack_root_logger=False,
        worker_log_color=False,

        # ── Security ─────────────────────────────────────────────────────────
        # Disable task result chord unlock (not needed, reduces attack surface)
        result_chord_retry_interval=False,
    )

    return app


# ── Module-level app instance ─────────────────────────────────────────────────
# This is what `celery -A workers.celery_app` discovers

app = create_celery_app()


# ── Signal handlers ───────────────────────────────────────────────────────────

@worker_init.connect
def on_worker_init(sender: Any, **kwargs: Any) -> None:
    """
    Called when a Celery worker process starts.
    Loads secrets, configures observability, and validates environment.
    """
    try:
        from security.secrets_loader import load_secrets  # noqa: PLC0415
        load_secrets()
    except Exception as exc:
        # Secrets load failure is fatal — worker cannot operate without keys
        raise RuntimeError(
            f"Worker startup failed: could not load secrets: {exc}"
        ) from exc

    try:
        from observability import setup_observability  # noqa: PLC0415
        setup_observability(service_name="complianceloop-worker")
    except Exception as exc:
        # Observability failure is NOT fatal — log and continue
        logging.warning("Observability setup failed (non-fatal): %s", exc)


@worker_ready.connect
def on_worker_ready(sender: Any, **kwargs: Any) -> None:
    """Called when the worker is fully initialised and ready to accept tasks."""
    import structlog  # noqa: PLC0415
    log = structlog.get_logger("workers.celery_app")
    log.info(
        "worker.ready",
        hostname=getattr(sender, "hostname", "unknown"),
        queues=list(TASK_ROUTES.keys())[:5],  # Log first 5 queue assignments
    )


@worker_shutdown.connect
def on_worker_shutdown(sender: Any, **kwargs: Any) -> None:
    """Called when the worker is shutting down. Close DB connections cleanly."""
    try:
        import asyncio  # noqa: PLC0415
        from db.engine import dispose_engines  # noqa: PLC0415
        asyncio.run(dispose_engines())
    except Exception:
        pass  # Shutdown errors are non-fatal


@task_prerun.connect
def on_task_prerun(
    task_id: str,
    task: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    **extra: Any,
) -> None:
    """
    Called before each task executes.
    Binds task-level context to structlog for the duration of the task.
    """
    try:
        from observability.logging_config import bind_contextvars  # noqa: PLC0415
        from structlog.contextvars import bind_contextvars  # noqa: PLC0415
        bind_contextvars(
            celery_task_id=task_id,
            celery_task_name=task.name,
        )
    except Exception:
        pass


@task_postrun.connect
def on_task_postrun(
    task_id: str,
    task: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    retval: Any,
    state: str,
    **extra: Any,
) -> None:
    """
    Called after each task completes (success or failure).
    Clears structlog context to prevent leakage between tasks.
    """
    try:
        from observability.logging_config import clear_pipeline_context  # noqa: PLC0415
        clear_pipeline_context()
    except Exception:
        pass


@task_failure.connect
def on_task_failure(
    task_id: str,
    exception: Exception,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    traceback: Any,
    einfo: Any,
    **extra: Any,
) -> None:
    """
    Called when a task fails after all retries are exhausted.
    Records error metrics and logs with full context.
    """
    try:
        import structlog  # noqa: PLC0415
        log = structlog.get_logger("workers.celery_app")
        log.error(
            "task.failed",
            task_id=task_id,
            exception_type=type(exception).__name__,
            exception_msg=str(exception),
        )

        from observability.metrics import PIPELINE_ERRORS_TOTAL  # noqa: PLC0415
        PIPELINE_ERRORS_TOTAL.labels(
            error_type=type(exception).__name__,
            is_demo="unknown",
        ).inc()
    except Exception:
        pass


@task_retry.connect
def on_task_retry(
    request: Any,
    reason: Any,
    einfo: Any,
    **extra: Any,
) -> None:
    """Called when a task is being retried."""
    try:
        import structlog  # noqa: PLC0415
        log = structlog.get_logger("workers.celery_app")
        log.warning(
            "task.retry",
            task_id=request.id,
            task_name=request.task,
            retries=request.retries,
            reason=str(reason),
        )
    except Exception:
        pass