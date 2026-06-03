"""
ComplianceLoop — Observability Module
=======================================
Unified entry point for all observability concerns:
  - Prometheus metrics (metrics.py)
  - Structured logging via structlog (logging_config.py)
  - OpenTelemetry distributed tracing stub (tracing.py)

Usage at application startup:
    from observability import setup_observability
    setup_observability()

Usage in application code:
    from observability import get_logger, metrics

    logger = get_logger(__name__)
    logger.info("pipeline.started", application_id=str(app.id))

    metrics.DECISION_TOTAL.labels(
        outcome="APPROVE",
        guideline_version_id=str(version.id),
        is_retro_eval="false",
        is_demo="false",
    ).inc()
"""

from observability.logging_config import (
    bind_agent_context,
    bind_pipeline_context,
    clear_pipeline_context,
    configure_logging,
    get_logger,
    unbind_agent_context,
)
from observability.tracing import (
    agent_span,
    audit_write_span,
    configure_tracing,
    faiss_retrieval_span,
    get_current_trace_id,
    get_tracer,
    pipeline_span,
    retro_eval_span,
)
from observability import metrics


def setup_observability(service_name: str = "complianceloop") -> None:
    """
    Initialise all observability systems in one call.

    Call this once at application startup — in FastAPI lifespan,
    Celery app initialisation, or CLI script entry points.

    Args:
        service_name: Service name for tracing backend registration.
    """
    configure_logging()
    configure_tracing(service_name=service_name)


__all__ = [
    # Setup
    "setup_observability",
    # Logging
    "configure_logging",
    "get_logger",
    "bind_pipeline_context",
    "bind_agent_context",
    "unbind_agent_context",
    "clear_pipeline_context",
    # Tracing
    "configure_tracing",
    "get_tracer",
    "get_current_trace_id",
    "pipeline_span",
    "agent_span",
    "audit_write_span",
    "faiss_retrieval_span",
    "retro_eval_span",
    # Metrics module (imported as namespace)
    "metrics",
]