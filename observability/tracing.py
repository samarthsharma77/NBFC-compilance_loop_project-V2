"""
ComplianceLoop — Distributed Tracing (OpenTelemetry)
=====================================================
OpenTelemetry tracing setup for ComplianceLoop.

Current status: STUB — tracing is architected but not yet wired to a
backend. The functions here are real and callable, but the default
configuration uses a NoOp tracer that produces zero overhead.

Why include it now?
  The pipeline code (graph.py, agents, audit writer) calls these functions
  to create spans. When a backend is configured (Jaeger, Tempo, OTLP),
  those spans automatically start reporting — zero code changes needed.

To enable tracing in production:
  1. Set OTEL_ENABLED=true
  2. Set OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317 (or Tempo endpoint)
  3. pip install opentelemetry-exporter-otlp-proto-grpc
  The tracer provider will auto-configure from env vars.

Spans created across the system:
  - complianceloop.pipeline.run       : full pipeline execution
  - complianceloop.agent.{name}       : individual agent execution
  - complianceloop.audit.write        : audit record write
  - complianceloop.retrieval.faiss    : FAISS index query
  - complianceloop.retrieval.llm      : LLM synthesis call
  - complianceloop.retro_eval.run     : single retro-eval execution
  - complianceloop.scraper.run        : regulatory scraper run

Span attributes follow OpenTelemetry semantic conventions where applicable,
with ComplianceLoop-specific attributes prefixed with 'compliance.'.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Generator, Optional

# ── Conditional OpenTelemetry import ─────────────────────────────────────────
# Import OpenTelemetry if available and enabled.
# If not available, all functions become no-ops — zero overhead.

_otel_enabled = os.environ.get("OTEL_ENABLED", "false").lower() == "true"
_tracer_configured = False

try:
    from opentelemetry import trace
    from opentelemetry.trace import Span, Status, StatusCode, Tracer
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    _otel_available = True
except ImportError:
    _otel_available = False
    # Create stub types so type hints don't fail
    Span = Any  # type: ignore[misc, assignment]
    Tracer = Any  # type: ignore[misc, assignment]


# ── Tracer provider setup ─────────────────────────────────────────────────────

def configure_tracing(service_name: str = "complianceloop") -> None:
    """
    Configure the OpenTelemetry tracer provider.

    Called once at application startup (api/main.py lifespan).
    If OTEL_ENABLED=false or opentelemetry-sdk is not installed,
    this is a safe no-op.

    Args:
        service_name: Service name reported to the tracing backend.
    """
    global _tracer_configured  # noqa: PLW0603

    if _tracer_configured:
        return

    if not _otel_available or not _otel_enabled:
        _tracer_configured = True
        return

    try:
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME  # noqa: PLC0415
        from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # noqa: PLC0415

        resource = Resource.create({SERVICE_NAME: service_name})
        provider = TracerProvider(resource=resource)

        # Configure exporter based on environment
        otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
        if otlp_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # noqa: PLC0415
                    OTLPSpanExporter,
                )
                exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
                provider.add_span_processor(BatchSpanProcessor(exporter))
            except ImportError:
                # OTLP exporter not installed — use no-op
                pass

        trace.set_tracer_provider(provider)
        _tracer_configured = True

    except Exception:
        # Tracing setup failure must never crash the application
        _tracer_configured = True


def get_tracer(name: str = "complianceloop") -> Any:
    """
    Get an OpenTelemetry tracer instance.

    Args:
        name: Instrumentation scope name. Typically the module path.

    Returns:
        OpenTelemetry Tracer if available and enabled, else a no-op tracer.
    """
    if not _otel_available or not _otel_enabled:
        return _NoOpTracer()
    try:
        from opentelemetry import trace  # noqa: PLC0415
        return trace.get_tracer(name)
    except Exception:
        return _NoOpTracer()


# ── Span context managers ─────────────────────────────────────────────────────

@contextmanager
def pipeline_span(
    application_id: str,
    guideline_version_id: str,
    is_retro_eval: bool = False,
    is_demo: bool = False,
) -> Generator[Any, None, None]:
    """
    Context manager for a full pipeline execution span.

    Usage:
        with pipeline_span(application_id=str(app.id), ...) as span:
            result = await run_pipeline(state)
            span.set_attribute("compliance.outcome", result.outcome)

    Args:
        application_id: Application being processed
        guideline_version_id: Active guideline version UUID
        is_retro_eval: Whether this is a retro-eval run
        is_demo: Demo context flag
    """
    tracer = get_tracer("complianceloop.pipeline")
    with tracer.start_as_current_span("complianceloop.pipeline.run") as span:
        span.set_attribute("compliance.application_id", application_id)
        span.set_attribute("compliance.guideline_version_id", guideline_version_id)
        span.set_attribute("compliance.is_retro_eval", is_retro_eval)
        span.set_attribute("compliance.is_demo", is_demo)
        try:
            yield span
        except Exception as exc:
            _set_span_error(span, exc)
            raise


@contextmanager
def agent_span(
    agent_name: str,
    application_id: str,
    is_demo: bool = False,
) -> Generator[Any, None, None]:
    """
    Context manager for a single agent execution span.

    Usage:
        with agent_span("document", application_id=...) as span:
            result = self._run_checks(state)
            span.set_attribute("compliance.signal_weight", result.signal_weight)

    Args:
        agent_name: document, sanctions, temporal, transaction, or rag
        application_id: Application being processed
        is_demo: Demo context flag
    """
    tracer = get_tracer(f"complianceloop.agent.{agent_name}")
    with tracer.start_as_current_span(f"complianceloop.agent.{agent_name}") as span:
        span.set_attribute("compliance.agent_name", agent_name)
        span.set_attribute("compliance.application_id", application_id)
        span.set_attribute("compliance.is_demo", is_demo)
        try:
            yield span
        except Exception as exc:
            _set_span_error(span, exc)
            raise


@contextmanager
def audit_write_span(
    decision_id: str,
    is_demo: bool = False,
) -> Generator[Any, None, None]:
    """
    Context manager for the pre-response audit write span.

    Args:
        decision_id: Decision UUID being audited
        is_demo: Demo context flag
    """
    tracer = get_tracer("complianceloop.audit")
    with tracer.start_as_current_span("complianceloop.audit.write") as span:
        span.set_attribute("compliance.decision_id", decision_id)
        span.set_attribute("compliance.is_demo", is_demo)
        try:
            yield span
        except Exception as exc:
            _set_span_error(span, exc)
            raise


@contextmanager
def faiss_retrieval_span(
    query_preview: str,
    top_k: int = 5,
) -> Generator[Any, None, None]:
    """
    Context manager for a FAISS index query span.

    Args:
        query_preview: First 100 chars of query for debugging
        top_k: Number of results requested
    """
    tracer = get_tracer("complianceloop.retrieval")
    with tracer.start_as_current_span("complianceloop.retrieval.faiss") as span:
        span.set_attribute("compliance.query_preview", query_preview[:100])
        span.set_attribute("compliance.top_k", top_k)
        try:
            yield span
        except Exception as exc:
            _set_span_error(span, exc)
            raise


@contextmanager
def retro_eval_span(
    application_id: str,
    guideline_version_id: str,
    is_demo: bool = False,
) -> Generator[Any, None, None]:
    """
    Context manager for a single retro-eval execution span.

    Args:
        application_id: Application being re-evaluated
        guideline_version_id: New guideline version triggering re-eval
        is_demo: Demo context flag
    """
    tracer = get_tracer("complianceloop.retro_eval")
    with tracer.start_as_current_span("complianceloop.retro_eval.run") as span:
        span.set_attribute("compliance.application_id", application_id)
        span.set_attribute("compliance.guideline_version_id", guideline_version_id)
        span.set_attribute("compliance.is_demo", is_demo)
        try:
            yield span
        except Exception as exc:
            _set_span_error(span, exc)
            raise


# ── Span utilities ────────────────────────────────────────────────────────────

def _set_span_error(span: Any, exc: Exception) -> None:
    """Mark a span as errored. Safe no-op if span is a stub."""
    try:
        if _otel_available and _otel_enabled:
            from opentelemetry.trace import Status, StatusCode  # noqa: PLC0415
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.record_exception(exc)
    except Exception:
        pass


def get_current_trace_id() -> str | None:
    """
    Get the current trace ID as a hex string.
    Returns None if tracing is disabled or no active span.
    Used to correlate logs with traces in Grafana.
    """
    try:
        if _otel_available and _otel_enabled:
            from opentelemetry import trace  # noqa: PLC0415
            ctx = trace.get_current_span().get_span_context()
            if ctx.is_valid:
                return format(ctx.trace_id, "032x")
    except Exception:
        pass
    return None


# ── No-op tracer stub ─────────────────────────────────────────────────────────

class _NoOpSpan:
    """Stub span that accepts any attribute set without doing anything."""

    def set_attribute(self, key: str, value: Any) -> None:  # noqa: ANN001
        pass

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        pass

    def record_exception(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __enter__(self) -> "_NoOpSpan":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class _NoOpTracer:
    """Stub tracer that produces zero overhead when OTEL is disabled."""

    @contextmanager
    def start_as_current_span(
        self, name: str, **kwargs: Any
    ) -> Generator[_NoOpSpan, None, None]:
        yield _NoOpSpan()