"""
ComplianceLoop — Structured Logging Configuration
===================================================
Configures structlog for JSON-structured logging across all services.

Every log line produced by this system contains:
  - timestamp       : ISO 8601 UTC
  - level           : debug/info/warning/error/critical
  - logger          : module path (e.g. pipeline.agents.document_agent)
  - event           : human-readable message
  - correlation_id  : UUID shared across all log lines for one pipeline run
  - application_id  : links logs to the specific application being processed
  - guideline_version_id : which regulation version was active
  - agent_name      : which agent produced this line (when applicable)
  - is_retro_eval   : distinguishes live from retro-eval runs
  - is_demo         : allows filtering demo traffic from production

Log output format:
  - Development: colourised, human-readable (ConsoleRenderer)
  - Production:  JSON (JSONRenderer) — parseable by Loki, Elasticsearch, CloudWatch

Correlation ID:
  Each pipeline run gets a UUID correlation_id injected into the context
  at the start of the LangGraph graph. All subsequent log calls in that
  run inherit it automatically via structlog's context vars support.
  This allows reconstructing the full trace of a single application's
  journey through the pipeline from logs alone.

Usage:
    # At application startup:
    from observability.logging_config import configure_logging
    configure_logging()

    # In any module:
    import structlog
    logger = structlog.get_logger(__name__)

    # With context:
    from observability.logging_config import bind_pipeline_context
    bind_pipeline_context(
        correlation_id="...",
        application_id="...",
        guideline_version_id="...",
        is_demo=False,
    )
    logger.info("pipeline.started", loan_amount=500000)

    # In agents (agent_name is bound automatically by BaseAgent):
    logger.info("agent.completed",
                signal_weight=0.85,
                findings_count=1,
                duration_ms=12)
"""

from __future__ import annotations

import logging
import logging.config
import os
import sys
from typing import Any

import structlog
from structlog.contextvars import merge_contextvars, clear_contextvars, bind_contextvars
from structlog.types import EventDict, WrappedLogger


# ── Custom processors ─────────────────────────────────────────────────────────

def _add_log_level(
    logger: WrappedLogger,
    method: str,
    event_dict: EventDict,
) -> EventDict:
    """
    Add the log level as a string field.
    structlog doesn't add it by default when using stdlib integration.
    """
    event_dict["level"] = method.upper()
    return event_dict


def _add_service_context(
    logger: WrappedLogger,
    method: str,
    event_dict: EventDict,
) -> EventDict:
    """
    Add static service-level context fields to every log line.
    These are set once from environment variables at startup.
    """
    event_dict.setdefault("service", "complianceloop")
    event_dict.setdefault("env", os.environ.get("APP_ENV", "development"))
    event_dict.setdefault("version", os.environ.get("APP_VERSION", "1.0.0"))
    return event_dict


def _drop_color_message(
    logger: WrappedLogger,
    method: str,
    event_dict: EventDict,
) -> EventDict:
    """
    Remove uvicorn's color_message field from log records.
    It duplicates the message field and adds ANSI codes to JSON output.
    """
    event_dict.pop("color_message", None)
    return event_dict


def _censor_sensitive_fields(
    logger: WrappedLogger,
    method: str,
    event_dict: EventDict,
) -> EventDict:
    """
    DPDP safety net: ensure PAN, Aadhaar, and raw key values never
    appear in logs even if a developer accidentally logs them.

    This processor scans all string values in the event dict for
    patterns that look like sensitive data and replaces them with [REDACTED].
    """
    import re  # noqa: PLC0415

    # PAN pattern: 5 uppercase letters + 4 digits + 1 uppercase letter
    PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
    # 12-digit number that could be Aadhaar
    AADHAAR_PATTERN = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
    # Hex strings that look like keys (64 chars = 32 bytes = potential HMAC key)
    KEY_PATTERN = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)

    def _censor_value(v: Any) -> Any:
        if not isinstance(v, str):
            return v
        v = PAN_PATTERN.sub("[PAN_REDACTED]", v)
        v = AADHAAR_PATTERN.sub("[AADHAAR_REDACTED]", v)
        v = KEY_PATTERN.sub("[KEY_REDACTED]", v)
        return v

    return {k: _censor_value(v) for k, v in event_dict.items()}


# ── Shared processor chain ────────────────────────────────────────────────────

def _build_processors(*, json_output: bool) -> list[Any]:
    """
    Build the structlog processor chain for the given output format.

    Args:
        json_output: If True, render to JSON. If False, render to colourised console.

    Returns:
        List of structlog processors.
    """
    shared_processors: list[Any] = [
        # Merge context vars (correlation_id, application_id, etc.)
        merge_contextvars,
        # Add stdlib log level
        _add_log_level,
        # Add service context
        _add_service_context,
        # Censor sensitive fields (DPDP safety net)
        _censor_sensitive_fields,
        # Remove uvicorn color_message
        _drop_color_message,
        # Add caller info (file, line) — only in non-JSON mode (too expensive in prod)
        *(
            [structlog.dev.set_exc_info]
            if not json_output
            else []
        ),
        # Add timestamp
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        # Stack info for exceptions
        structlog.processors.StackInfoRenderer(),
        # Format exceptions
        structlog.processors.format_exc_info,
        # Render to JSON or console
        (
            structlog.processors.JSONRenderer()
            if json_output
            else structlog.dev.ConsoleRenderer(colors=True)
        ),
    ]
    return shared_processors


# ── Public API ────────────────────────────────────────────────────────────────

def configure_logging() -> None:
    """
    Configure structlog and stdlib logging for the ComplianceLoop application.

    Call once at application startup:
      - In FastAPI: called in api/main.py lifespan
      - In Celery: called in workers/celery_app.py
      - In CLI scripts: called at module top level

    Behaviour:
      - Production (APP_ENV=production or STAGING): JSON output to stdout
      - Development: colourised console output to stdout
      - Log level: controlled by LOG_LEVEL env var (default: INFO)

    Also configures stdlib logging to route through structlog so that
    third-party libraries (SQLAlchemy, httpx, uvicorn) produce structured output.
    """
    app_env = os.environ.get("APP_ENV", "development").lower()
    json_output = app_env in ("production", "staging")
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()

    processors = _build_processors(json_output=json_output)

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level, logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging to route through structlog
    # This ensures SQLAlchemy, httpx, uvicorn, etc. produce structured output
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "structlog": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processors": processors,
                    "foreign_pre_chain": [
                        structlog.stdlib.add_log_level,
                        structlog.stdlib.add_logger_name,
                        structlog.processors.TimeStamper(fmt="iso", utc=True),
                    ],
                }
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "structlog",
                }
            },
            "loggers": {
                # Root logger
                "": {
                    "handlers": ["stdout"],
                    "level": log_level,
                    "propagate": False,
                },
                # Silence noisy libraries in production
                "sqlalchemy.engine": {
                    "level": "WARNING" if json_output else log_level,
                },
                "sqlalchemy.pool": {
                    "level": "WARNING",
                },
                "alembic": {
                    "level": "INFO",
                    "handlers": ["stdout"],
                    "propagate": False,
                },
                "httpx": {
                    "level": "WARNING",
                },
                "uvicorn.access": {
                    "level": "INFO" if not json_output else "WARNING",
                },
                "celery": {
                    "level": log_level,
                },
                "celery.task": {
                    "level": log_level,
                },
                "scrapy": {
                    "level": "WARNING",
                },
            },
        }
    )


# ── Context binding helpers ───────────────────────────────────────────────────

def bind_pipeline_context(
    correlation_id: str,
    application_id: str,
    guideline_version_id: str,
    is_retro_eval: bool = False,
    is_demo: bool = False,
    run_number: int = 1,
) -> None:
    """
    Bind pipeline run context to structlog's context vars.

    All subsequent log calls in the same async context will include
    these fields automatically. Called at the start of each pipeline run
    by the router node.

    Args:
        correlation_id: UUID for this pipeline run (not the application_id —
                        one application may have multiple runs)
        application_id: Application being processed
        guideline_version_id: Active guideline version
        is_retro_eval: Whether this is a retro-eval run
        is_demo: Demo context flag
        run_number: Pipeline run number (1=original, 2+=retro-eval)
    """
    bind_contextvars(
        correlation_id=correlation_id,
        application_id=application_id,
        guideline_version_id=guideline_version_id,
        is_retro_eval=is_retro_eval,
        is_demo=is_demo,
        run_number=run_number,
    )


def bind_agent_context(agent_name: str) -> None:
    """
    Add agent_name to the current context.
    Called by BaseAgent at the start of each agent's run() method.

    Args:
        agent_name: document, sanctions, temporal, transaction, or rag
    """
    bind_contextvars(agent_name=agent_name)


def unbind_agent_context() -> None:
    """Remove agent_name from context after agent execution completes."""
    from structlog.contextvars import unbind_contextvars  # noqa: PLC0415
    unbind_contextvars("agent_name")


def clear_pipeline_context() -> None:
    """
    Clear all pipeline context vars.
    Called at the end of each pipeline run to prevent context leakage
    between Celery tasks that reuse the same worker thread.
    """
    clear_contextvars()


def get_logger(name: str) -> Any:
    """
    Get a structlog logger bound to the given module name.

    Convenience wrapper — equivalent to structlog.get_logger(name).
    All application code should use this instead of stdlib logging.get_logger()
    to ensure consistent structured output.

    Args:
        name: Module name, typically __name__

    Returns:
        structlog BoundLogger instance

    Usage:
        logger = get_logger(__name__)
        logger.info("application.received", application_id=str(app.id))
    """
    return structlog.get_logger(name)