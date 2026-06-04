"""
ComplianceLoop — Celery Beat Schedule
=======================================
Defines all periodic tasks executed by Celery Beat.

Beat is a single-instance scheduler — it triggers tasks at defined intervals
by publishing messages to the appropriate queues. The actual execution
happens in the worker processes, not in the Beat process itself.

CRITICAL: Beat must run as exactly ONE instance. Running multiple Beat
instances causes duplicate task execution (double scraping, double calibration,
double retention wipes). In docker-compose.yml, the `beat` service has
deploy.replicas=1 enforced.

Schedule overview:
  ┌────────────────────────────────────────┬──────────────┬──────────┐
  │ Task                                   │ Interval     │ Queue    │
  ├────────────────────────────────────────┼──────────────┼──────────┤
  │ scrape RBI circulars                   │ 6 hours      │ scraper  │
  │ scrape RBI KYC amendments              │ 12 hours     │ scraper  │
  │ scrape DPDP portal                     │ 12 hours     │ scraper  │
  │ scrape MCA notifications               │ 24 hours     │ scraper  │
  │ update UNSC/OFAC watchlists            │ 6 hours      │ scraper  │
  │ update MHA watchlist                   │ 24 hours     │ scraper  │
  │ nightly calibration engine             │ daily 02:00  │ calib.   │
  │ confidence drift stats                 │ daily 02:30  │ calib.   │
  │ DPDP retention enforcement             │ daily 03:00  │ calib.   │
  │ MinIO upload retry for pending audits  │ 30 minutes   │ calib.   │
  │ notification outbox poll               │ 60 seconds   │ notif.   │
  │ FAISS index age gauge update           │ 15 minutes   │ scraper  │
  │ retro-eval queue depth gauge update    │ 5 minutes    │ calib.   │
  └────────────────────────────────────────┴──────────────┴──────────┘

All intervals are read from environment variables with safe defaults,
allowing operational adjustment without code changes.
"""

from __future__ import annotations

import os
from celery.schedules import crontab

# ── Interval helpers ──────────────────────────────────────────────────────────

def _hours(env_var: str, default: int) -> int:
    """Read an interval (hours) from env var, falling back to default."""
    return int(os.environ.get(env_var, str(default)))


def _minutes(env_var: str, default: int) -> int:
    """Read an interval (minutes) from env var, falling back to default."""
    return int(os.environ.get(env_var, str(default)))


# ── Beat schedule definition ──────────────────────────────────────────────────

BEAT_SCHEDULE: dict[str, dict] = {

    # ── Regulatory scrapers ──────────────────────────────────────────────────

    "scrape-rbi-circulars": {
        "task": "scraper.tasks.scrape_rbi_circulars",
        "schedule": _hours("SCRAPER_INTERVAL_RBI_HOURS", 6) * 3600,
        "options": {"queue": "scraper", "expires": 3600 * 5},
        "kwargs": {"source": "rbi_circulars"},
    },

    "scrape-rbi-kyc": {
        "task": "scraper.tasks.scrape_rbi_kyc",
        "schedule": _hours("SCRAPER_INTERVAL_KYC_HOURS", 12) * 3600,
        "options": {"queue": "scraper", "expires": 3600 * 11},
        "kwargs": {"source": "rbi_kyc"},
    },

    "scrape-dpdp-portal": {
        "task": "scraper.tasks.scrape_dpdp_portal",
        "schedule": _hours("SCRAPER_INTERVAL_DPDP_HOURS", 12) * 3600,
        "options": {"queue": "scraper", "expires": 3600 * 11},
        "kwargs": {"source": "dpdp_portal"},
    },

    "scrape-mca-notifications": {
        "task": "scraper.tasks.scrape_mca_notifications",
        "schedule": _hours("SCRAPER_INTERVAL_MCA_HOURS", 24) * 3600,
        "options": {"queue": "scraper", "expires": 3600 * 23},
        "kwargs": {"source": "mca"},
    },

    # ── Watchlist updates ────────────────────────────────────────────────────

    "update-watchlists-unsc-ofac": {
        "task": "scraper.tasks.update_watchlists",
        "schedule": int(os.environ.get("WATCHLIST_UPDATE_INTERVAL_UN", "21600")),
        "options": {"queue": "scraper", "expires": 21600 - 300},
        "kwargs": {"lists": ["unsc", "ofac"]},
    },

    "update-watchlist-mha": {
        "task": "scraper.tasks.update_watchlists",
        "schedule": int(os.environ.get("WATCHLIST_UPDATE_INTERVAL_MHA", "86400")),
        "options": {"queue": "scraper", "expires": 86400 - 600},
        "kwargs": {"lists": ["mha"]},
    },

    # ── Calibration engine ───────────────────────────────────────────────────

    "nightly-calibration": {
        "task": "calibration.tasks.run_nightly_calibration",
        # Daily at 02:00 UTC — quiet period for NBFC operations
        "schedule": crontab(
            hour=str(int(os.environ.get("CALIBRATION_RUN_HOUR", "2"))),
            minute="0",
        ),
        "options": {"queue": "calibration", "expires": 3600},
    },

    "confidence-drift-stats": {
        "task": "calibration.tasks.update_drift_stats",
        # Daily at 02:30 UTC — 30 minutes after calibration run
        "schedule": crontab(
            hour=str(int(os.environ.get("CALIBRATION_RUN_HOUR", "2"))),
            minute="30",
        ),
        "options": {"queue": "calibration", "expires": 3600},
    },

    # ── DPDP retention enforcement ───────────────────────────────────────────

    "dpdp-retention-enforcement": {
        "task": "dpdp.retention_enforcer.run_retention_wipe",
        # Daily at 03:00 UTC — after calibration completes
        "schedule": crontab(hour="3", minute="0"),
        "options": {"queue": "calibration", "expires": 7200},
    },

    # ── Audit MinIO upload retry ─────────────────────────────────────────────

    "retry-pending-minio-uploads": {
        "task": "audit.s3_uploader.retry_pending_uploads",
        # Every 30 minutes — ensures MinIO backlog is cleared
        "schedule": _minutes("MINIO_RETRY_INTERVAL_MINUTES", 30) * 60,
        "options": {"queue": "calibration", "expires": 1500},
    },

    # ── Notification outbox poll ─────────────────────────────────────────────

    "poll-notification-outbox": {
        "task": "workers.notification_worker.poll_outbox",
        # Every 60 seconds — fast polling for at-least-once delivery
        "schedule": _minutes("NOTIFICATION_POLL_INTERVAL_SECONDS", 60),
        "options": {"queue": "notifications", "expires": 55},
    },

    # ── Observability gauge updates ──────────────────────────────────────────

    "update-faiss-index-age-gauge": {
        "task": "scraper.tasks.update_faiss_index_age_gauge",
        # Every 15 minutes — keeps Prometheus FAISS age gauge current
        "schedule": _minutes("FAISS_AGE_GAUGE_INTERVAL_MINUTES", 15) * 60,
        "options": {"queue": "scraper", "expires": 840},
    },

    "update-retro-eval-queue-depth": {
        "task": "retro_eval.tasks.update_queue_depth_gauge",
        # Every 5 minutes — monitors retro-eval backlog
        "schedule": _minutes("RETRO_EVAL_DEPTH_GAUGE_INTERVAL_MINUTES", 5) * 60,
        "options": {"queue": "calibration", "expires": 240},
    },

    "update-notification-outbox-pending-gauge": {
        "task": "workers.notification_worker.update_outbox_pending_gauge",
        # Every 5 minutes
        "schedule": 300,
        "options": {"queue": "notifications", "expires": 240},
    },

    # ── PostgreSQL backup ────────────────────────────────────────────────────

    "nightly-postgres-backup": {
        "task": "workers.notification_worker.noop_task",
        # Daily at 01:00 UTC — before calibration runs
        # NOTE: actual backup is done by scripts/pg_backup.sh via cron on host
        # This Beat entry is a placeholder/reminder — the real backup is host-side
        "schedule": crontab(hour="1", minute="0"),
        "options": {"queue": "calibration", "expires": 3600},
    },
}