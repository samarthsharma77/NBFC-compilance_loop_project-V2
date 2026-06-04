"""
ComplianceLoop — Celery Queue Definitions
==========================================
Defines all Celery queues used across the system.

Queue architecture:
  - pipeline       : Live application compliance pipeline runs (highest priority)
  - retro_eval     : Retroactive re-evaluation jobs (rate-limited, lower priority)
  - scraper        : Regulatory scraper and watchlist update tasks
  - notifications  : Notification outbox delivery (email + webhook)
  - calibration    : Nightly calibration engine and drift monitor

Priority ordering (higher number = higher priority in Redis):
  pipeline=10, notifications=8, retro_eval=5, scraper=3, calibration=1

This separation ensures:
  1. Live pipeline runs are never starved by retro-eval backlogs
  2. Scraper tasks don't compete with notification delivery
  3. Calibration (nightly, low urgency) never blocks anything
  4. Each queue can be scaled independently (separate worker pools)

Worker routing:
  - complianceloop_worker    : pipeline, retro_eval, notifications
  - complianceloop_scraper   : scraper only
  - complianceloop_beat      : triggers scheduled tasks (no queue consumption)
"""

from __future__ import annotations

from kombu import Exchange, Queue

# ── Exchange definitions ──────────────────────────────────────────────────────

# Default direct exchange — one queue per routing key
default_exchange = Exchange("complianceloop", type="direct")

# Dead letter exchange — failed tasks land here after max retries
dlx_exchange = Exchange("complianceloop.dlx", type="direct")


# ── Queue definitions ─────────────────────────────────────────────────────────

#: Live compliance pipeline runs — highest priority
#: Workers: complianceloop_worker
#: Tasks: pipeline.tasks.run_pipeline, pipeline.tasks.run_pipeline_sync
PIPELINE_QUEUE = Queue(
    name="pipeline",
    exchange=default_exchange,
    routing_key="pipeline",
    queue_arguments={
        "x-max-priority": 10,
        "x-dead-letter-exchange": "complianceloop.dlx",
        "x-dead-letter-routing-key": "pipeline.dead",
        "x-message-ttl": 300_000,       # 5 minutes — stale pipeline tasks discarded
    },
)

#: Retroactive re-evaluation jobs — rate-limited, lower priority
#: Workers: complianceloop_worker
#: Tasks: retro_eval.tasks.retro_eval_single
RETRO_EVAL_QUEUE = Queue(
    name="retro_eval",
    exchange=default_exchange,
    routing_key="retro_eval",
    queue_arguments={
        "x-max-priority": 5,
        "x-dead-letter-exchange": "complianceloop.dlx",
        "x-dead-letter-routing-key": "retro_eval.dead",
        "x-message-ttl": 3_600_000,     # 1 hour TTL — retro-eval tasks can wait
    },
)

#: Regulatory scraper and watchlist updates
#: Workers: complianceloop_scraper_worker (dedicated)
#: Tasks: scraper.tasks.scrape_all, scraper.tasks.update_watchlists
SCRAPER_QUEUE = Queue(
    name="scraper",
    exchange=default_exchange,
    routing_key="scraper",
    queue_arguments={
        "x-max-priority": 3,
        "x-dead-letter-exchange": "complianceloop.dlx",
        "x-dead-letter-routing-key": "scraper.dead",
        "x-message-ttl": 43_200_000,    # 12 hours — scraper tasks are periodic
    },
)

#: Notification outbox delivery
#: Workers: complianceloop_worker
#: Tasks: workers.notification_worker.deliver_notification
NOTIFICATIONS_QUEUE = Queue(
    name="notifications",
    exchange=default_exchange,
    routing_key="notifications",
    queue_arguments={
        "x-max-priority": 8,
        "x-dead-letter-exchange": "complianceloop.dlx",
        "x-dead-letter-routing-key": "notifications.dead",
        "x-message-ttl": 86_400_000,    # 24 hours
    },
)

#: Nightly calibration engine and retention enforcement
#: Workers: complianceloop_worker (beat triggers, worker executes)
#: Tasks: calibration.tasks.run_nightly_calibration, dpdp.retention_enforcer
CALIBRATION_QUEUE = Queue(
    name="calibration",
    exchange=default_exchange,
    routing_key="calibration",
    queue_arguments={
        "x-max-priority": 1,
        "x-dead-letter-exchange": "complianceloop.dlx",
        "x-dead-letter-routing-key": "calibration.dead",
        "x-message-ttl": 86_400_000,    # 24 hours
    },
)

# ── Dead letter queues ────────────────────────────────────────────────────────
# Tasks that exhaust retries land here for inspection

PIPELINE_DLQ = Queue(
    name="pipeline.dead",
    exchange=dlx_exchange,
    routing_key="pipeline.dead",
)

RETRO_EVAL_DLQ = Queue(
    name="retro_eval.dead",
    exchange=dlx_exchange,
    routing_key="retro_eval.dead",
)

SCRAPER_DLQ = Queue(
    name="scraper.dead",
    exchange=dlx_exchange,
    routing_key="scraper.dead",
)

NOTIFICATIONS_DLQ = Queue(
    name="notifications.dead",
    exchange=dlx_exchange,
    routing_key="notifications.dead",
)

CALIBRATION_DLQ = Queue(
    name="calibration.dead",
    exchange=dlx_exchange,
    routing_key="calibration.dead",
)

# ── All queues list (used in celery_app.py config) ────────────────────────────

ALL_QUEUES = (
    PIPELINE_QUEUE,
    RETRO_EVAL_QUEUE,
    SCRAPER_QUEUE,
    NOTIFICATIONS_QUEUE,
    CALIBRATION_QUEUE,
    PIPELINE_DLQ,
    RETRO_EVAL_DLQ,
    SCRAPER_DLQ,
    NOTIFICATIONS_DLQ,
    CALIBRATION_DLQ,
)

# ── Routing map (task name → queue) ──────────────────────────────────────────
# Used as task_routes in celery_app.py

TASK_ROUTES: dict[str, dict[str, str]] = {
    # Pipeline tasks
    "pipeline.tasks.run_pipeline":             {"queue": "pipeline"},
    "pipeline.tasks.run_pipeline_sync":        {"queue": "pipeline"},
    # Retro-eval tasks
    "retro_eval.tasks.retro_eval_single":      {"queue": "retro_eval"},
    "retro_eval.tasks.enqueue_retro_eval_batch": {"queue": "retro_eval"},
    # Scraper tasks
    "scraper.tasks.scrape_rbi_circulars":      {"queue": "scraper"},
    "scraper.tasks.scrape_rbi_kyc":            {"queue": "scraper"},
    "scraper.tasks.scrape_dpdp_portal":        {"queue": "scraper"},
    "scraper.tasks.scrape_mca_notifications":  {"queue": "scraper"},
    "scraper.tasks.scrape_all":                {"queue": "scraper"},
    "scraper.tasks.update_watchlists":         {"queue": "scraper"},
    "scraper.tasks.update_watchlist_unsc":     {"queue": "scraper"},
    "scraper.tasks.update_watchlist_ofac":     {"queue": "scraper"},
    "scraper.tasks.update_watchlist_mha":      {"queue": "scraper"},
    # Notification tasks
    "workers.notification_worker.deliver_notification":  {"queue": "notifications"},
    "workers.notification_worker.poll_outbox":           {"queue": "notifications"},
    # Calibration tasks
    "calibration.tasks.run_nightly_calibration": {"queue": "calibration"},
    "calibration.tasks.update_drift_stats":      {"queue": "calibration"},
    # DPDP retention task
    "dpdp.retention_enforcer.run_retention_wipe": {"queue": "calibration"},
    # Audit MinIO upload retry
    "audit.s3_uploader.retry_pending_uploads":   {"queue": "calibration"},
}