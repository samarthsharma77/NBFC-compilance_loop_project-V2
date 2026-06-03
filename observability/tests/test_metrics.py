"""
Tests for observability/metrics.py and observability/logging_config.py

Covers:
  - All Prometheus metric objects exist and have correct types
  - Counter, Histogram, Gauge labels work without errors
  - record_pipeline_run() records to correct metrics
  - record_agent_run() records to correct metrics
  - update_calibration_gauges() sets gauge values
  - structlog configure_logging() runs without error
  - bind_pipeline_context() / clear_pipeline_context() work
  - Sensitive field censoring in log processor
  - get_logger() returns usable logger
  - No metric name collisions (duplicate registration would raise)
"""

from __future__ import annotations

import os
import uuid

import pytest
from prometheus_client import (
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def set_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set required env vars for logging config tests."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("APP_VERSION", "1.0.0-test")


# ── Imports under test ────────────────────────────────────────────────────────
# Import after env is set
from observability.metrics import (  # noqa: E402
    AGENT_DURATION,
    AGENT_ERRORS_TOTAL,
    AGENT_FINDINGS_TOTAL,
    AGENT_SIGNAL_WEIGHT,
    API_RATE_LIMITED_TOTAL,
    API_REQUEST_DURATION,
    API_REQUESTS_TOTAL,
    AUDIT_MINIO_UPLOAD_PENDING,
    AUDIT_MINIO_UPLOAD_TOTAL,
    AUDIT_WRITE_DURATION,
    AUDIT_WRITE_ERRORS_TOTAL,
    CALIBRATION_CONFIDENCE_DRIFT_STDDEV,
    CALIBRATION_OVERRIDE_RATE,
    CALIBRATION_RUN_TOTAL,
    CALIBRATION_THRESHOLD_APPROVE,
    CALIBRATION_THRESHOLD_REVIEW,
    DECISION_COMPOSITE_SCORE,
    DECISION_CONFIDENCE,
    DECISION_TOTAL,
    DPDP_BREACH_FLAGS_TOTAL,
    DPDP_CONSENT_CHECKS_TOTAL,
    DPDP_RETENTION_WIPES_TOTAL,
    FAISS_INDEX_AGE_HOURS,
    FAISS_INDEX_SWAP_TOTAL,
    GUIDELINE_VERSION_AGE_HOURS,
    NOTIFICATION_FAILED_TOTAL,
    NOTIFICATION_OUTBOX_PENDING,
    NOTIFICATION_SENT_TOTAL,
    PIPELINE_DURATION,
    PIPELINE_ERRORS_TOTAL,
    PIPELINE_RUNS_TOTAL,
    RAG_LLM_DURATION,
    RAG_RETRIEVAL_DURATION,
    RETRO_EVAL_APPLICATIONS_TOTAL,
    RETRO_EVAL_DECISION_CHANGES_TOTAL,
    RETRO_EVAL_DURATION,
    RETRO_EVAL_QUEUE_DEPTH,
    RETRO_EVAL_TRIGGERED_TOTAL,
    SANCTIONS_CACHE_HIT_RATE,
    SANCTIONS_CACHE_OPERATIONS_TOTAL,
    SANCTIONS_LOOKUP_TOTAL,
    SCRAPER_CHANGES_DETECTED_TOTAL,
    SCRAPER_RUNS_TOTAL,
    SYSTEM_INFO,
    WATCHLIST_UPDATE_AGE_HOURS,
    record_agent_run,
    record_pipeline_run,
    update_calibration_gauges,
)


# ── Metric type tests ─────────────────────────────────────────────────────────

class TestMetricTypes:
    """Verify each metric is the correct Prometheus type."""

    def test_pipeline_duration_is_histogram(self) -> None:
        assert isinstance(PIPELINE_DURATION, Histogram)

    def test_pipeline_runs_total_is_counter(self) -> None:
        assert isinstance(PIPELINE_RUNS_TOTAL, Counter)

    def test_pipeline_errors_total_is_counter(self) -> None:
        assert isinstance(PIPELINE_ERRORS_TOTAL, Counter)

    def test_decision_total_is_counter(self) -> None:
        assert isinstance(DECISION_TOTAL, Counter)

    def test_decision_confidence_is_histogram(self) -> None:
        assert isinstance(DECISION_CONFIDENCE, Histogram)

    def test_decision_composite_score_is_histogram(self) -> None:
        assert isinstance(DECISION_COMPOSITE_SCORE, Histogram)

    def test_agent_duration_is_histogram(self) -> None:
        assert isinstance(AGENT_DURATION, Histogram)

    def test_agent_signal_weight_is_histogram(self) -> None:
        assert isinstance(AGENT_SIGNAL_WEIGHT, Histogram)

    def test_agent_findings_total_is_counter(self) -> None:
        assert isinstance(AGENT_FINDINGS_TOTAL, Counter)

    def test_agent_errors_total_is_counter(self) -> None:
        assert isinstance(AGENT_ERRORS_TOTAL, Counter)

    def test_audit_write_duration_is_histogram(self) -> None:
        assert isinstance(AUDIT_WRITE_DURATION, Histogram)

    def test_audit_write_errors_is_counter(self) -> None:
        assert isinstance(AUDIT_WRITE_ERRORS_TOTAL, Counter)

    def test_audit_minio_upload_pending_is_gauge(self) -> None:
        assert isinstance(AUDIT_MINIO_UPLOAD_PENDING, Gauge)

    def test_retro_eval_queue_depth_is_gauge(self) -> None:
        assert isinstance(RETRO_EVAL_QUEUE_DEPTH, Gauge)

    def test_retro_eval_triggered_is_counter(self) -> None:
        assert isinstance(RETRO_EVAL_TRIGGERED_TOTAL, Counter)

    def test_retro_eval_decision_changes_is_counter(self) -> None:
        assert isinstance(RETRO_EVAL_DECISION_CHANGES_TOTAL, Counter)

    def test_retro_eval_duration_is_histogram(self) -> None:
        assert isinstance(RETRO_EVAL_DURATION, Histogram)

    def test_calibration_threshold_approve_is_gauge(self) -> None:
        assert isinstance(CALIBRATION_THRESHOLD_APPROVE, Gauge)

    def test_calibration_threshold_review_is_gauge(self) -> None:
        assert isinstance(CALIBRATION_THRESHOLD_REVIEW, Gauge)

    def test_calibration_confidence_drift_is_gauge(self) -> None:
        assert isinstance(CALIBRATION_CONFIDENCE_DRIFT_STDDEV, Gauge)

    def test_calibration_override_rate_is_gauge(self) -> None:
        assert isinstance(CALIBRATION_OVERRIDE_RATE, Gauge)

    def test_sanctions_cache_hit_rate_is_gauge(self) -> None:
        assert isinstance(SANCTIONS_CACHE_HIT_RATE, Gauge)

    def test_faiss_index_age_is_gauge(self) -> None:
        assert isinstance(FAISS_INDEX_AGE_HOURS, Gauge)

    def test_guideline_version_age_is_gauge(self) -> None:
        assert isinstance(GUIDELINE_VERSION_AGE_HOURS, Gauge)

    def test_notification_outbox_pending_is_gauge(self) -> None:
        assert isinstance(NOTIFICATION_OUTBOX_PENDING, Gauge)

    def test_dpdp_consent_checks_is_counter(self) -> None:
        assert isinstance(DPDP_CONSENT_CHECKS_TOTAL, Counter)

    def test_dpdp_retention_wipes_is_counter(self) -> None:
        assert isinstance(DPDP_RETENTION_WIPES_TOTAL, Counter)

    def test_dpdp_breach_flags_is_counter(self) -> None:
        assert isinstance(DPDP_BREACH_FLAGS_TOTAL, Counter)


# ── Label correctness tests ───────────────────────────────────────────────────

class TestMetricLabels:
    """Verify metrics accept their defined labels without raising."""

    def test_pipeline_duration_labels(self) -> None:
        PIPELINE_DURATION.labels(
            outcome="APPROVE",
            is_retro_eval="false",
            is_demo="false",
        ).observe(0.5)

    def test_decision_total_labels(self) -> None:
        DECISION_TOTAL.labels(
            outcome="REJECT",
            guideline_version_id=str(uuid.uuid4()),
            is_retro_eval="false",
            is_demo="false",
        ).inc()

    def test_agent_duration_all_agents(self) -> None:
        """All five agent names should be valid labels."""
        for agent in ["document", "sanctions", "temporal", "transaction", "rag"]:
            AGENT_DURATION.labels(
                agent_name=agent,
                status="pass",
                is_demo="false",
            ).observe(0.01)

    def test_agent_findings_total_labels(self) -> None:
        AGENT_FINDINGS_TOTAL.labels(
            agent_name="document",
            severity="FAIL",
            finding_code="DOC_INCOME_PROOF_MISSING",
            is_demo="false",
        ).inc()

    def test_retro_eval_decision_changes_labels(self) -> None:
        RETRO_EVAL_DECISION_CHANGES_TOTAL.labels(
            old_outcome="APPROVE",
            new_outcome="REJECT",
            is_demo="false",
        ).inc()

    def test_calibration_override_rate_label(self) -> None:
        CALIBRATION_OVERRIDE_RATE.labels(confidence_band="0.60-0.65").set(0.42)

    def test_watchlist_update_age_labels(self) -> None:
        for list_name in ["unsc", "ofac", "mha", "sebi", "rbi_defaulter"]:
            WATCHLIST_UPDATE_AGE_HOURS.labels(list_name=list_name).set(3.5)

    def test_scraper_runs_total_labels(self) -> None:
        for source in ["rbi_circulars", "rbi_kyc", "dpdp_portal", "mca"]:
            for status in ["success", "parse_error", "network_error", "no_change"]:
                SCRAPER_RUNS_TOTAL.labels(source=source, status=status).inc(0)

    def test_notification_sent_total_labels(self) -> None:
        NOTIFICATION_SENT_TOTAL.labels(
            notification_type="DECISION_CHANGE",
            channel="EMAIL",
            is_demo="false",
        ).inc()

    def test_audit_write_duration_labels(self) -> None:
        AUDIT_WRITE_DURATION.labels(
            status="success",
            is_demo="false",
        ).observe(0.003)

    def test_dpdp_consent_checks_results(self) -> None:
        for result in ["pass", "fail_missing", "fail_stale_version", "fail_expired_timestamp"]:
            DPDP_CONSENT_CHECKS_TOTAL.labels(result=result).inc(0)


# ── Helper function tests ─────────────────────────────────────────────────────

class TestRecordPipelineRun:

    def test_basic_approve_run(self) -> None:
        """record_pipeline_run records without raising for APPROVE outcome."""
        record_pipeline_run(
            outcome="APPROVE",
            duration_seconds=1.23,
            confidence=0.95,
            composite_score=0.88,
            guideline_version_id=str(uuid.uuid4()),
            is_retro_eval=False,
            is_demo=False,
        )

    def test_retro_eval_review_run(self) -> None:
        """record_pipeline_run works for retro-eval REVIEW outcome."""
        record_pipeline_run(
            outcome="REVIEW",
            duration_seconds=0.87,
            confidence=0.65,
            composite_score=0.62,
            guideline_version_id=str(uuid.uuid4()),
            is_retro_eval=True,
            is_demo=False,
        )

    def test_demo_reject_run(self) -> None:
        """record_pipeline_run works for demo REJECT outcome."""
        record_pipeline_run(
            outcome="REJECT",
            duration_seconds=0.45,
            confidence=0.98,
            composite_score=0.32,
            guideline_version_id=str(uuid.uuid4()),
            is_retro_eval=False,
            is_demo=True,
        )

    def test_all_outcomes_recorded(self) -> None:
        """All three outcomes are valid."""
        version_id = str(uuid.uuid4())
        for outcome in ["APPROVE", "REVIEW", "REJECT"]:
            record_pipeline_run(
                outcome=outcome,
                duration_seconds=0.5,
                confidence=0.75,
                composite_score=0.70,
                guideline_version_id=version_id,
                is_retro_eval=False,
                is_demo=False,
            )


class TestRecordAgentRun:

    def test_all_agents_all_statuses(self) -> None:
        """record_agent_run works for all five agents and all status values."""
        for agent in ["document", "sanctions", "temporal", "transaction", "rag"]:
            for status in ["pass", "fail", "warn", "error", "skip"]:
                record_agent_run(
                    agent_name=agent,
                    status=status,
                    duration_seconds=0.01,
                    signal_weight=0.75,
                    is_demo=False,
                )

    def test_zero_signal_weight(self) -> None:
        """Signal weight of 0.0 (sanctions FAIL) is valid."""
        record_agent_run(
            agent_name="sanctions",
            status="fail",
            duration_seconds=0.002,
            signal_weight=0.0,
            is_demo=False,
        )

    def test_max_signal_weight(self) -> None:
        """Signal weight of 1.0 (clean pass) is valid."""
        record_agent_run(
            agent_name="document",
            status="pass",
            duration_seconds=0.012,
            signal_weight=1.0,
            is_demo=False,
        )


class TestUpdateCalibrationGauges:

    def test_updates_approve_threshold(self) -> None:
        update_calibration_gauges(
            approve_threshold=0.84,
            review_threshold=0.62,
            confidence_stddev_7d=0.08,
        )
        # Verify Prometheus gauge was set — sample() returns value
        samples = list(CALIBRATION_THRESHOLD_APPROVE.collect())[0].samples
        assert any(s.value == pytest.approx(0.84) for s in samples)

    def test_updates_review_threshold(self) -> None:
        update_calibration_gauges(
            approve_threshold=0.82,
            review_threshold=0.58,
            confidence_stddev_7d=None,  # No drift data yet
        )
        samples = list(CALIBRATION_THRESHOLD_REVIEW.collect())[0].samples
        assert any(s.value == pytest.approx(0.58) for s in samples)

    def test_none_stddev_does_not_raise(self) -> None:
        """None confidence_stddev_7d is valid (insufficient data)."""
        update_calibration_gauges(
            approve_threshold=0.82,
            review_threshold=0.60,
            confidence_stddev_7d=None,
        )

    def test_drift_alert_threshold_value(self) -> None:
        """Verify drift value is correctly set."""
        update_calibration_gauges(
            approve_threshold=0.82,
            review_threshold=0.60,
            confidence_stddev_7d=0.17,
        )
        samples = list(CALIBRATION_CONFIDENCE_DRIFT_STDDEV.collect())[0].samples
        assert any(s.value == pytest.approx(0.17) for s in samples)


# ── Logging config tests ──────────────────────────────────────────────────────

class TestLoggingConfig:

    def test_configure_logging_does_not_raise(self) -> None:
        from observability.logging_config import configure_logging  # noqa: PLC0415
        configure_logging()  # Should not raise

    def test_get_logger_returns_logger(self) -> None:
        from observability.logging_config import get_logger  # noqa: PLC0415
        logger = get_logger("test.module")
        assert logger is not None

    def test_logger_info_does_not_raise(self) -> None:
        from observability.logging_config import configure_logging, get_logger  # noqa: PLC0415
        configure_logging()
        logger = get_logger("test.pipeline")
        logger.info("test.event", key="value", number=42)

    def test_bind_and_clear_pipeline_context(self) -> None:
        from observability.logging_config import (  # noqa: PLC0415
            bind_pipeline_context,
            clear_pipeline_context,
            configure_logging,
        )
        configure_logging()
        bind_pipeline_context(
            correlation_id=str(uuid.uuid4()),
            application_id=str(uuid.uuid4()),
            guideline_version_id=str(uuid.uuid4()),
            is_retro_eval=False,
            is_demo=True,
        )
        # Should not raise
        clear_pipeline_context()

    def test_bind_agent_context(self) -> None:
        from observability.logging_config import (  # noqa: PLC0415
            bind_agent_context,
            clear_pipeline_context,
            configure_logging,
        )
        configure_logging()
        bind_agent_context("document")
        clear_pipeline_context()

    def test_sensitive_field_censoring_pan(self) -> None:
        """PAN patterns in log values are redacted by the censor processor."""
        from observability.logging_config import _censor_sensitive_fields  # noqa: PLC0415

        event = {"event": "test", "raw": "applicant PAN is ABCDE1234F in this message"}
        result = _censor_sensitive_fields(None, "info", event)  # type: ignore[arg-type]
        assert "ABCDE1234F" not in result["raw"]
        assert "[PAN_REDACTED]" in result["raw"]

    def test_sensitive_field_censoring_key(self) -> None:
        """64-char hex strings (potential keys) are redacted."""
        from observability.logging_config import _censor_sensitive_fields  # noqa: PLC0415

        fake_key = "a" * 64
        event = {"event": "key_logged", "key": fake_key}
        result = _censor_sensitive_fields(None, "info", event)  # type: ignore[arg-type]
        assert fake_key not in result["key"]
        assert "[KEY_REDACTED]" in result["key"]

    def test_non_sensitive_values_not_censored(self) -> None:
        """Normal values are passed through unchanged."""
        from observability.logging_config import _censor_sensitive_fields  # noqa: PLC0415

        event = {
            "event": "pipeline.started",
            "application_id": str(uuid.uuid4()),
            "outcome": "APPROVE",
            "confidence": 0.95,
        }
        result = _censor_sensitive_fields(None, "info", event)  # type: ignore[arg-type]
        assert result["outcome"] == "APPROVE"
        assert result["confidence"] == 0.95


# ── Tracing tests ─────────────────────────────────────────────────────────────

class TestTracing:

    def test_configure_tracing_does_not_raise(self) -> None:
        from observability.tracing import configure_tracing  # noqa: PLC0415
        configure_tracing()  # NoOp when OTEL_ENABLED=false

    def test_pipeline_span_context_manager(self) -> None:
        from observability.tracing import pipeline_span  # noqa: PLC0415
        with pipeline_span(
            application_id=str(uuid.uuid4()),
            guideline_version_id=str(uuid.uuid4()),
            is_retro_eval=False,
            is_demo=False,
        ) as span:
            span.set_attribute("compliance.outcome", "APPROVE")

    def test_agent_span_context_manager(self) -> None:
        from observability.tracing import agent_span  # noqa: PLC0415
        with agent_span(
            agent_name="document",
            application_id=str(uuid.uuid4()),
            is_demo=False,
        ) as span:
            span.set_attribute("compliance.signal_weight", 0.85)

    def test_audit_write_span(self) -> None:
        from observability.tracing import audit_write_span  # noqa: PLC0415
        with audit_write_span(decision_id=str(uuid.uuid4()), is_demo=False):
            pass

    def test_faiss_retrieval_span(self) -> None:
        from observability.tracing import faiss_retrieval_span  # noqa: PLC0415
        with faiss_retrieval_span(query_preview="FOIR threshold exceeded", top_k=5):
            pass

    def test_retro_eval_span(self) -> None:
        from observability.tracing import retro_eval_span  # noqa: PLC0415
        with retro_eval_span(
            application_id=str(uuid.uuid4()),
            guideline_version_id=str(uuid.uuid4()),
            is_demo=True,
        ):
            pass

    def test_span_exception_does_not_swallow_error(self) -> None:
        """Exceptions inside span context managers are re-raised."""
        from observability.tracing import pipeline_span  # noqa: PLC0415
        with pytest.raises(ValueError, match="test error"):
            with pipeline_span(
                application_id=str(uuid.uuid4()),
                guideline_version_id=str(uuid.uuid4()),
            ):
                raise ValueError("test error")

    def test_get_current_trace_id_returns_none_when_disabled(self) -> None:
        from observability.tracing import get_current_trace_id  # noqa: PLC0415
        result = get_current_trace_id()
        assert result is None  # OTEL disabled in test env

    def test_get_tracer_returns_noop_when_disabled(self) -> None:
        from observability.tracing import get_tracer, _NoOpTracer  # noqa: PLC0415
        tracer = get_tracer("test")
        assert isinstance(tracer, _NoOpTracer)


# ── setup_observability integration test ──────────────────────────────────────

class TestSetupObservability:

    def test_setup_observability_runs_without_error(self) -> None:
        from observability import setup_observability  # noqa: PLC0415
        setup_observability(service_name="complianceloop-test")

    def test_setup_observability_idempotent(self) -> None:
        """Calling setup_observability twice should not raise."""
        from observability import setup_observability  # noqa: PLC0415
        setup_observability()
        setup_observability()  # Second call — should be safe no-op