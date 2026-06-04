"""
ComplianceLoop — Workers Package
==================================
Celery worker infrastructure for async task execution.

This package provides:
  - celery_app  : The Celery application instance (entry point for CLI)
  - queues      : Queue and routing definitions
  - schedules   : Celery Beat periodic task schedule
  - notification_worker : Outbox polling and notification delivery tasks

The Beat schedule is applied to the app here so that importing `workers`
is sufficient to have the full schedule registered — no separate
configuration step needed.

Usage:
    # Start worker (consumes pipeline, retro_eval, notifications queues):
    celery -A workers.celery_app worker --queues=pipeline,retro_eval,notifications

    # Start Beat scheduler:
    celery -A workers.celery_app beat

    # Start Flower monitoring UI:
    celery -A workers.celery_app flower
"""

from workers.celery_app import app
from workers.schedules import BEAT_SCHEDULE

# Apply the Beat schedule to the Celery app
app.conf.beat_schedule = BEAT_SCHEDULE

__all__ = ["app", "BEAT_SCHEDULE"]