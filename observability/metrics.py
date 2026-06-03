"""
ComplianceLoop — Prometheus Metrics
=====================================
Defines ALL Prometheus metrics used across the system.

All metrics are defined here in one place so:
  1. There are no duplicate metric registration errors (common Prometheus pitfall)
  2. The full metric catalogue is visible in one file
  3. Metric names follow a consistent naming convention

Naming convention: compliance_<subsystem>_<measurement>_<unit>
  - compliance_pipeline_duration_seconds
  - compliance_agent_duration_seconds
  - compliance_decision_total
  etc.

Metric types used:
  - Counter   : monotonically increasing (decisions, errors, notifications sent)
  - Histogram : latency distributions (pipeline duration, agent duration, RAG retrieval)
  - Gauge     : current state values (queue depth, thresholds, index age)

Subsystems:
  - pipeline   : LangGraph pipeline execution
  - agent      : Individual specialist agents
  - audit      : Audit write operations
  - retro_eval : Retroactive re-evaluation loop
  - scraper    : Regulatory scraper
  - calibration: Calibration engine
  - retrieval  : FAISS index and embedding
  - sanctions  : Sanctions cache and lookup
  - dpdp       : DPDP consent and retention
  - notification: Outbox delivery
  - api        : HTTP API layer

Usage:
    from observability.metrics import PIPELINE_DURATION, DECISION_TOTAL
    with PIPELINE_DURATION.labels(outcome="APPROVE", is_retro_eval="false").time():
        result = await run_pipeline(...)
    DECISION_TOTAL.labels(outcome=result.outcome, guideline_version=version_id).inc()
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info

# ── Histogram bucket definitions ──────────────────────────────────────────────

# Pipeline / agent latency buckets (seconds): 50ms to 60s
LATENCY_BUCKETS_SECONDS = (
    0.05, 0.1, 0.25, 0.5, 0.75,
    1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0,
)

# RAG retrieval latency buckets (milliseconds): 10ms to 5000ms
RETRIEVAL_LATENCY_BUCKETS_MS = (
    10, 25, 50, 100, 250, 500, 750,
    1000, 2000, 3000, 5000,
)

# Confidence score buckets: 0.0 to 1.0 in 0.05 steps
CONFIDENCE_BUCKETS = tuple(round(i * 0.05, 2) for i in range(21))


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE METRICS
# ═══════════════════════════════════════════════════════════════════════════════

PIPELINE_DURATION = Histogram(
    name="compliance_pipeline_duration_seconds",
    documentation=(
        "End-to-end LangGraph pipeline execution time in seconds. "
        "Measured from task start to audit write completion (pre-response). "
        "Labels: outcome (APPROVE/REVIEW/REJECT), is_retro_eval (true/false), is_demo (true/false)."
    ),
    labelnames=["outcome", "is_retro_eval", "is_demo"],
    buckets=LATENCY_BUCKETS_SECONDS,
)

PIPELINE_RUNS_TOTAL = Counter(
    name="compliance_pipeline_runs_total",
    documentation=(
        "Total number of pipeline execution attempts. "
        "Labels: status (success/error/timeout), is_retro_eval, is_demo."
    ),
    labelnames=["status", "is_retro_eval", "is_demo"],
)

PIPELINE_ERRORS_TOTAL = Counter(
    name="compliance_pipeline_errors_total",
    documentation=(
        "Total pipeline execution errors by error type. "
        "Labels: error_type (agent_error/state_error/audit_error/timeout), is_demo."
    ),
    labelnames=["error_type", "is_demo"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# DECISION METRICS
# ═══════════════════════════════════════════════════════════════════════════════

DECISION_TOTAL = Counter(
    name="compliance_decision_total",
    documentation=(
        "Total decisions by outcome. "
        "Labels: outcome (APPROVE/REVIEW/REJECT), guideline_version_id, is_retro_eval, is_demo."
    ),
    labelnames=["outcome", "guideline_version_id", "is_retro_eval", "is_demo"],
)

DECISION_CONFIDENCE = Histogram(
    name="compliance_decision_confidence_score",
    documentation=(
        "Distribution of confidence scores for pipeline decisions. "
        "Used by calibration engine to compute rolling stats and detect drift. "
        "Labels: outcome, is_retro_eval, is_demo."
    ),
    labelnames=["outcome", "is_retro_eval", "is_demo"],
    buckets=CONFIDENCE_BUCKETS,
)

DECISION_COMPOSITE_SCORE = Histogram(
    name="compliance_decision_composite_score",
    documentation=(
        "Distribution of composite scores (pre-threshold weighted aggregate). "
        "Labels: outcome, is_demo."
    ),
    labelnames=["outcome", "is_demo"],
    buckets=CONFIDENCE_BUCKETS,
)


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT METRICS
# ═══════════════════════════════════════════════════════════════════════════════

AGENT_DURATION = Histogram(
    name="compliance_agent_duration_seconds",
    documentation=(
        "Per-agent execution time in seconds. "
        "Labels: agent_name (document/sanctions/temporal/transaction/rag), "
        "status (pass/fail/warn/error/skip), is_demo."
    ),
    labelnames=["agent_name", "status", "is_demo"],
    buckets=LATENCY_BUCKETS_SECONDS,
)

AGENT_SIGNAL_WEIGHT = Histogram(
    name="compliance_agent_signal_weight",
    documentation=(
        "Distribution of signal_weight values returned by each agent. "
        "Values 0.0–1.0. Used to detect systematic agent degradation. "
        "Labels: agent_name, is_demo."
    ),
    labelnames=["agent_name", "is_demo"],
    buckets=CONFIDENCE_BUCKETS,
)

AGENT_FINDINGS_TOTAL = Counter(
    name="compliance_agent_findings_total",
    documentation=(
        "Total agent findings by type. "
        "Labels: agent_name, severity (PASS/FAIL/WARN), finding_code, is_demo."
    ),
    labelnames=["agent_name", "severity", "finding_code", "is_demo"],
)

AGENT_ERRORS_TOTAL = Counter(
    name="compliance_agent_errors_total",
    documentation=(
        "Total agent execution errors. An error means the agent returned "
        "status=ERROR and the decision node routed to REVIEW. "
        "Labels: agent_name, error_type, is_demo."
    ),
    labelnames=["agent_name", "error_type", "is_demo"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT METRICS
# ═══════════════════════════════════════════════════════════════════════════════

AUDIT_WRITE_DURATION = Histogram(
    name="compliance_audit_write_duration_seconds",
    documentation=(
        "Time taken to write the audit record (Postgres + MinIO queue). "
        "This is a critical path operation — must complete before API responds. "
        "Labels: status (success/postgres_error/minio_queue_error), is_demo."
    ),
    labelnames=["status", "is_demo"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
)

AUDIT_WRITE_ERRORS_TOTAL = Counter(
    name="compliance_audit_write_errors_total",
    documentation=(
        "CRITICAL: Total audit write failures. Any non-zero value requires "
        "immediate investigation — compliance evidence may be missing. "
        "Labels: error_type (postgres/minio/hash/hmac), is_demo."
    ),
    labelnames=["error_type", "is_demo"],
)

AUDIT_MINIO_UPLOAD_TOTAL = Counter(
    name="compliance_audit_minio_upload_total",
    documentation=(
        "MinIO payload upload attempts. "
        "Labels: status (success/error/retry), is_demo."
    ),
    labelnames=["status", "is_demo"],
)

AUDIT_MINIO_UPLOAD_PENDING = Gauge(
    name="compliance_audit_minio_upload_pending",
    documentation=(
        "Number of audit records with payload_s3_uploaded=false "
        "(MinIO upload pending or failed). Should be near 0. "
        "Labels: is_demo."
    ),
    labelnames=["is_demo"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# RETRO-EVAL METRICS
# ═══════════════════════════════════════════════════════════════════════════════

RETRO_EVAL_QUEUE_DEPTH = Gauge(
    name="compliance_retro_eval_queue_depth",
    documentation=(
        "Number of pending re-evaluation tasks in the Celery retro_eval queue. "
        "Alert fires at > 10,000. "
        "Labels: is_demo."
    ),
    labelnames=["is_demo"],
)

RETRO_EVAL_TRIGGERED_TOTAL = Counter(
    name="compliance_retro_eval_triggered_total",
    documentation=(
        "Total retro-eval batch triggers (one per guideline version activation). "
        "Labels: guideline_version_id, affected_tags, is_demo."
    ),
    labelnames=["guideline_version_id", "affected_tags", "is_demo"],
)

RETRO_EVAL_APPLICATIONS_TOTAL = Counter(
    name="compliance_retro_eval_applications_total",
    documentation=(
        "Total application re-evaluations completed. "
        "Labels: decision_changed (true/false), is_demo."
    ),
    labelnames=["decision_changed", "is_demo"],
)

RETRO_EVAL_DECISION_CHANGES_TOTAL = Counter(
    name="compliance_retro_eval_decision_changes_total",
    documentation=(
        "Total decision changes from retro-eval runs. "
        "Labels: old_outcome, new_outcome, is_demo."
    ),
    labelnames=["old_outcome", "new_outcome", "is_demo"],
)

RETRO_EVAL_DURATION = Histogram(
    name="compliance_retro_eval_duration_seconds",
    documentation=(
        "Time taken to complete a single application retro-eval. "
        "Labels: decision_changed, is_demo."
    ),
    labelnames=["decision_changed", "is_demo"],
    buckets=LATENCY_BUCKETS_SECONDS,
)


# ═══════════════════════════════════════════════════════════════════════════════
# REGULATORY SCRAPER METRICS
# ═══════════════════════════════════════════════════════════════════════════════

SCRAPER_RUNS_TOTAL = Counter(
    name="compliance_scraper_runs_total",
    documentation=(
        "Total scraper runs by source. "
        "Labels: source (rbi_circulars/rbi_kyc/dpdp_portal/mca), "
        "status (success/parse_error/network_error/no_change)."
    ),
    labelnames=["source", "status"],
)

SCRAPER_CHANGES_DETECTED_TOTAL = Counter(
    name="compliance_scraper_changes_detected_total",
    documentation=(
        "Total regulatory changes detected by the scraper delta detector. "
        "Labels: source, change_type (new_circular/updated_circular)."
    ),
    labelnames=["source", "change_type"],
)

GUIDELINE_VERSION_AGE_HOURS = Gauge(
    name="compliance_guideline_version_age_hours",
    documentation=(
        "Hours since the current active guideline version was last updated. "
        "Alert fires if > 48 hours (stale index risk). "
        "Labels: none (one value for the overall system)."
    ),
    labelnames=[],
)

FAISS_INDEX_AGE_HOURS = Gauge(
    name="compliance_faiss_index_age_hours",
    documentation=(
        "Hours since the active FAISS index was last rebuilt. "
        "Alert fires if > 48 hours. "
        "Labels: none."
    ),
    labelnames=[],
)

WATCHLIST_UPDATE_AGE_HOURS = Gauge(
    name="compliance_watchlist_update_age_hours",
    documentation=(
        "Hours since each sanctions watchlist was last refreshed. "
        "Labels: list_name (unsc/ofac/mha/sebi/rbi_defaulter)."
    ),
    labelnames=["list_name"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# RETRIEVAL (FAISS) METRICS
# ═══════════════════════════════════════════════════════════════════════════════

RAG_RETRIEVAL_DURATION = Histogram(
    name="compliance_rag_retrieval_duration_ms",
    documentation=(
        "FAISS query duration in milliseconds, including embedding computation. "
        "Labels: status (success/error), is_demo."
    ),
    labelnames=["status", "is_demo"],
    buckets=RETRIEVAL_LATENCY_BUCKETS_MS,
)

RAG_LLM_DURATION = Histogram(
    name="compliance_rag_llm_duration_seconds",
    documentation=(
        "LLM synthesis call duration in seconds (Ollama/Groq). "
        "Labels: status (success/error/timeout/schema_validation_failed), is_demo."
    ),
    labelnames=["status", "is_demo"],
    buckets=LATENCY_BUCKETS_SECONDS,
)

FAISS_INDEX_SWAP_TOTAL = Counter(
    name="compliance_faiss_index_swap_total",
    documentation=(
        "Total FAISS index swap attempts. "
        "Labels: status (success/health_check_failed/error)."
    ),
    labelnames=["status"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# SANCTIONS METRICS
# ═══════════════════════════════════════════════════════════════════════════════

SANCTIONS_LOOKUP_TOTAL = Counter(
    name="compliance_sanctions_lookup_total",
    documentation=(
        "Total sanctions screening lookups. "
        "Labels: result (pass/fail_pan_hit/warn_name_match/warn_defaulter), is_demo."
    ),
    labelnames=["result", "is_demo"],
)

SANCTIONS_CACHE_HIT_RATE = Gauge(
    name="compliance_sanctions_cache_hit_rate",
    documentation=(
        "Redis sanctions cache hit percentage (0.0–1.0). "
        "Low values indicate cache invalidation issues. "
        "Labels: none."
    ),
    labelnames=[],
)

SANCTIONS_CACHE_OPERATIONS_TOTAL = Counter(
    name="compliance_sanctions_cache_operations_total",
    documentation=(
        "Total sanctions cache operations. "
        "Labels: operation (hit/miss/invalidate/rebuild), list_name."
    ),
    labelnames=["operation", "list_name"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# CALIBRATION METRICS
# ═══════════════════════════════════════════════════════════════════════════════

CALIBRATION_THRESHOLD_APPROVE = Gauge(
    name="compliance_calibration_threshold_approve",
    documentation=(
        "Current APPROVE decision threshold (composite_score >= this → APPROVE). "
        "Tracked as a time-series to show calibration engine adjustments. "
        "Alert fires if threshold changes by > 0.15 in 30 days. "
        "Labels: none."
    ),
    labelnames=[],
)

CALIBRATION_THRESHOLD_REVIEW = Gauge(
    name="compliance_calibration_threshold_review",
    documentation=(
        "Current REVIEW threshold (composite_score >= this → REVIEW, else REJECT). "
        "Labels: none."
    ),
    labelnames=[],
)

CALIBRATION_CONFIDENCE_DRIFT_STDDEV = Gauge(
    name="compliance_confidence_drift_7d_stddev",
    documentation=(
        "7-day rolling standard deviation of confidence scores. "
        "Alert fires if > 0.15 (confidence drift — may signal regulatory change impact). "
        "Labels: none."
    ),
    labelnames=[],
)

CALIBRATION_OVERRIDE_RATE = Gauge(
    name="compliance_calibration_override_rate",
    documentation=(
        "Reviewer override rate per confidence band. "
        "High override rate in a band means the pipeline is miscalibrated there. "
        "Labels: confidence_band (e.g. '0.60-0.65')."
    ),
    labelnames=["confidence_band"],
)

CALIBRATION_RUN_TOTAL = Counter(
    name="compliance_calibration_run_total",
    documentation=(
        "Total calibration engine runs. "
        "Labels: status (success/no_data/error), threshold_changed (true/false)."
    ),
    labelnames=["status", "threshold_changed"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# DPDP METRICS
# ═══════════════════════════════════════════════════════════════════════════════

DPDP_CONSENT_CHECKS_TOTAL = Counter(
    name="compliance_dpdp_consent_checks_total",
    documentation=(
        "Total DPDP consent gate checks at API layer. "
        "Labels: result (pass/fail_missing/fail_stale_version/fail_expired_timestamp)."
    ),
    labelnames=["result"],
)

DPDP_RETENTION_WIPES_TOTAL = Counter(
    name="compliance_dpdp_retention_wipes_total",
    documentation=(
        "Total PII retention wipes performed by retention_enforcer. "
        "Labels: status (success/error), is_demo."
    ),
    labelnames=["status", "is_demo"],
)

DPDP_BREACH_FLAGS_TOTAL = Counter(
    name="compliance_dpdp_breach_flags_total",
    documentation=(
        "Total audit records flagged via break_glass procedure. "
        "Any non-zero value is a critical event. "
        "Labels: is_demo."
    ),
    labelnames=["is_demo"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION METRICS
# ═══════════════════════════════════════════════════════════════════════════════

NOTIFICATION_SENT_TOTAL = Counter(
    name="compliance_notification_sent_total",
    documentation=(
        "Total notifications successfully delivered. "
        "Labels: notification_type, channel (EMAIL/WEBHOOK), is_demo."
    ),
    labelnames=["notification_type", "channel", "is_demo"],
)

NOTIFICATION_FAILED_TOTAL = Counter(
    name="compliance_notification_failed_total",
    documentation=(
        "Total notification delivery failures (after all retries exhausted). "
        "Labels: notification_type, channel, failure_reason, is_demo."
    ),
    labelnames=["notification_type", "channel", "failure_reason", "is_demo"],
)

NOTIFICATION_OUTBOX_PENDING = Gauge(
    name="compliance_notification_outbox_pending",
    documentation=(
        "Current count of PENDING notifications in outbox. "
        "High values indicate notification worker is falling behind. "
        "Labels: is_demo."
    ),
    labelnames=["is_demo"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# API METRICS
# ═══════════════════════════════════════════════════════════════════════════════

API_REQUEST_DURATION = Histogram(
    name="compliance_api_request_duration_seconds",
    documentation=(
        "HTTP API request duration in seconds. "
        "Labels: method, endpoint, status_code, is_demo."
    ),
    labelnames=["method", "endpoint", "status_code", "is_demo"],
    buckets=LATENCY_BUCKETS_SECONDS,
)

API_REQUESTS_TOTAL = Counter(
    name="compliance_api_requests_total",
    documentation=(
        "Total HTTP API requests. "
        "Labels: method, endpoint, status_code, is_demo."
    ),
    labelnames=["method", "endpoint", "status_code", "is_demo"],
)

API_RATE_LIMITED_TOTAL = Counter(
    name="compliance_api_rate_limited_total",
    documentation=(
        "Total requests rejected by rate limiter. "
        "Labels: endpoint."
    ),
    labelnames=["endpoint"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM INFO
# ═══════════════════════════════════════════════════════════════════════════════

SYSTEM_INFO = Info(
    name="compliance_system",
    documentation="ComplianceLoop system information.",
)

# Set system info at import time — static values
SYSTEM_INFO.info({
    "version": "1.0.0",
    "service": "complianceloop",
})


# ── Helper functions ──────────────────────────────────────────────────────────

def record_pipeline_run(
    outcome: str,
    duration_seconds: float,
    confidence: float,
    composite_score: float,
    guideline_version_id: str,
    is_retro_eval: bool,
    is_demo: bool,
) -> None:
    """
    Record all metrics for a completed pipeline run in one call.

    Called by the pipeline runner after each successful or failed run.
    This is the primary metric recording entry point for the pipeline.

    Args:
        outcome: APPROVE, REVIEW, or REJECT
        duration_seconds: Total pipeline execution time
        confidence: Decision confidence score 0.0–1.0
        composite_score: Weighted aggregate score 0.0–1.0
        guideline_version_id: UUID string of guideline version used
        is_retro_eval: Whether this was a retro-eval run
        is_demo: Whether this was a demo pipeline run
    """
    retro = str(is_retro_eval).lower()
    demo = str(is_demo).lower()

    PIPELINE_DURATION.labels(
        outcome=outcome, is_retro_eval=retro, is_demo=demo
    ).observe(duration_seconds)

    PIPELINE_RUNS_TOTAL.labels(
        status="success", is_retro_eval=retro, is_demo=demo
    ).inc()

    DECISION_TOTAL.labels(
        outcome=outcome,
        guideline_version_id=guideline_version_id,
        is_retro_eval=retro,
        is_demo=demo,
    ).inc()

    DECISION_CONFIDENCE.labels(
        outcome=outcome, is_retro_eval=retro, is_demo=demo
    ).observe(confidence)

    DECISION_COMPOSITE_SCORE.labels(
        outcome=outcome, is_demo=demo
    ).observe(composite_score)


def record_agent_run(
    agent_name: str,
    status: str,
    duration_seconds: float,
    signal_weight: float,
    is_demo: bool,
) -> None:
    """
    Record metrics for a single agent execution.

    Args:
        agent_name: document, sanctions, temporal, transaction, or rag
        status: pass, fail, warn, error, or skip
        duration_seconds: Agent execution time
        signal_weight: Agent output signal weight 0.0–1.0
        is_demo: Demo context flag
    """
    demo = str(is_demo).lower()

    AGENT_DURATION.labels(
        agent_name=agent_name, status=status, is_demo=demo
    ).observe(duration_seconds)

    AGENT_SIGNAL_WEIGHT.labels(
        agent_name=agent_name, is_demo=demo
    ).observe(signal_weight)


def update_calibration_gauges(
    approve_threshold: float,
    review_threshold: float,
    confidence_stddev_7d: float | None,
) -> None:
    """
    Update calibration-related Gauges.
    Called by the calibration engine after each run and by the
    /v1/calibration/status endpoint to keep Prometheus in sync.

    Args:
        approve_threshold: Current approve threshold
        review_threshold: Current review threshold
        confidence_stddev_7d: 7-day rolling stddev (None if insufficient data)
    """
    CALIBRATION_THRESHOLD_APPROVE.set(approve_threshold)
    CALIBRATION_THRESHOLD_REVIEW.set(review_threshold)
    if confidence_stddev_7d is not None:
        CALIBRATION_CONFIDENCE_DRIFT_STDDEV.set(confidence_stddev_7d)