"""
ComplianceLoop — Notification Worker
======================================
Celery tasks for delivering notifications from the transactional outbox.

Architecture — transactional outbox pattern:
  When a retro-eval run changes a decision, the retro_eval module writes
  notification rows to the notification_outbox table in the SAME database
  transaction as the Decision and AuditRecord. This guarantees that if
  the transaction commits, the notification will eventually be delivered.

  This worker polls the outbox table, delivers pending notifications via
  the appropriate channel (EMAIL or WEBHOOK), and updates status atomically.

  Delivery uses SELECT ... FOR UPDATE SKIP LOCKED to safely handle
  multiple concurrent worker instances without double-delivery.

Retry strategy:
  - Max 3 attempts (configurable via max_retries column per notification)
  - Exponential backoff: 60s, 120s, 240s
  - After max retries: status → FAILED, failure_reason recorded
  - Dead letter: FAILED rows remain in DB for audit/manual intervention

DPDP note:
  Notifications may contain personal data (application_id, decision outcome).
  They are delivered over TLS (SMTP/HTTPS). The notification content does NOT
  include raw PII like PAN, Aadhaar, or full name — only UUIDs and decision
  outcomes. The full payload is the JSONB stored in notification_outbox.payload.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog

from workers.celery_app import app

logger = structlog.get_logger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────

# Batch size for outbox poll — how many notifications to fetch per poll cycle
OUTBOX_POLL_BATCH_SIZE = 100

# Exponential backoff delays (seconds) indexed by retry_count
RETRY_BACKOFF_SECONDS = {0: 60, 1: 120, 2: 240, 3: 480}


# ── Outbox poll task (triggered by Beat every 60 seconds) ────────────────────

@app.task(
    name="workers.notification_worker.poll_outbox",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    queue="notifications",
    ignore_result=True,
)
def poll_outbox(self: Any) -> None:
    """
    Poll the notification_outbox table and enqueue delivery tasks.

    Fetches up to OUTBOX_POLL_BATCH_SIZE PENDING notifications that are
    due for delivery and enqueues individual deliver_notification tasks.

    This task itself is lightweight — it only reads the outbox and
    enqueues delivery tasks. Actual delivery happens in deliver_notification.
    """
    try:
        asyncio.run(_poll_outbox_async())
    except Exception as exc:
        logger.error("outbox.poll.failed", error=str(exc))
        raise self.retry(exc=exc) from exc


async def _poll_outbox_async() -> None:
    """Async implementation of outbox polling."""
    from db.session import get_session_context  # noqa: PLC0415
    from models.notification_outbox import NotificationOutbox, NotificationStatus  # noqa: PLC0415
    from sqlalchemy import select, and_, or_  # noqa: PLC0415
    from sqlalchemy.dialects.postgresql import insert  # noqa: PLC0415

    now = datetime.now(timezone.utc)

    async with get_session_context() as db:
        # Fetch pending notifications due for delivery
        # SKIP LOCKED prevents multiple workers from picking the same row
        stmt = (
            select(NotificationOutbox)
            .where(
                and_(
                    NotificationOutbox.status == NotificationStatus.PENDING,
                    or_(
                        NotificationOutbox.next_retry_at.is_(None),
                        NotificationOutbox.next_retry_at <= now,
                    ),
                )
            )
            .order_by(NotificationOutbox.created_at.asc())
            .limit(OUTBOX_POLL_BATCH_SIZE)
            .with_for_update(skip_locked=True)
        )

        result = await db.execute(stmt)
        notifications = result.scalars().all()

        if not notifications:
            return

        logger.info("outbox.poll.found", count=len(notifications))

        for notification in notifications:
            # Enqueue individual delivery task
            deliver_notification.apply_async(
                kwargs={"notification_id": str(notification.id)},
                queue="notifications",
            )

        await db.commit()


# ── Individual delivery task ──────────────────────────────────────────────────

@app.task(
    name="workers.notification_worker.deliver_notification",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    queue="notifications",
    ignore_result=False,
)
def deliver_notification(self: Any, notification_id: str) -> dict[str, Any]:
    """
    Deliver a single notification from the outbox.

    Fetches the notification row, delivers via the appropriate channel
    (EMAIL or WEBHOOK), and updates status atomically.

    Args:
        notification_id: UUID string of the NotificationOutbox row.

    Returns:
        Dict with delivery result: {status, channel, notification_id}
    """
    try:
        return asyncio.run(_deliver_notification_async(notification_id))
    except Exception as exc:
        logger.error(
            "notification.delivery.failed",
            notification_id=notification_id,
            error=str(exc),
            retries=self.request.retries,
        )
        # Exponential backoff retry
        backoff = RETRY_BACKOFF_SECONDS.get(self.request.retries, 480)
        raise self.retry(exc=exc, countdown=backoff) from exc


async def _deliver_notification_async(notification_id: str) -> dict[str, Any]:
    """Async implementation of notification delivery."""
    from db.session import get_session_context  # noqa: PLC0415
    from models.notification_outbox import (  # noqa: PLC0415
        NotificationChannel,
        NotificationOutbox,
        NotificationStatus,
    )
    from sqlalchemy import select  # noqa: PLC0415
    import uuid  # noqa: PLC0415

    async with get_session_context() as db:
        # Fetch notification with row lock
        stmt = (
            select(NotificationOutbox)
            .where(NotificationOutbox.id == uuid.UUID(notification_id))
            .with_for_update()
        )
        result = await db.execute(stmt)
        notification = result.scalar_one_or_none()

        if notification is None:
            logger.warning(
                "notification.not_found",
                notification_id=notification_id,
            )
            return {"status": "not_found", "notification_id": notification_id}

        # Skip if already delivered (idempotency guard)
        if notification.status == NotificationStatus.SENT:
            return {
                "status": "already_sent",
                "notification_id": notification_id,
            }

        # Skip if suppressed
        if notification.status == NotificationStatus.SUPPRESSED:
            return {
                "status": "suppressed",
                "notification_id": notification_id,
            }

        # Check max retries
        if notification.retry_count >= notification.max_retries:
            notification.status = NotificationStatus.FAILED
            notification.failure_reason = f"Max retries ({notification.max_retries}) exhausted"
            await db.commit()

            from observability.metrics import NOTIFICATION_FAILED_TOTAL  # noqa: PLC0415
            NOTIFICATION_FAILED_TOTAL.labels(
                notification_type=notification.notification_type.value,
                channel=notification.channel.value,
                failure_reason="max_retries_exhausted",
                is_demo=str(notification.is_demo).lower(),
            ).inc()

            return {
                "status": "failed_max_retries",
                "notification_id": notification_id,
            }

        # ── Attempt delivery ──────────────────────────────────────────────────
        try:
            if notification.channel == NotificationChannel.EMAIL:
                await _deliver_email(notification)
            elif notification.channel == NotificationChannel.WEBHOOK:
                await _deliver_webhook(notification)

            # Mark as sent
            notification.status = NotificationStatus.SENT
            notification.sent_at = datetime.now(timezone.utc)
            notification.failure_reason = None
            await db.commit()

            from observability.metrics import NOTIFICATION_SENT_TOTAL  # noqa: PLC0415
            NOTIFICATION_SENT_TOTAL.labels(
                notification_type=notification.notification_type.value,
                channel=notification.channel.value,
                is_demo=str(notification.is_demo).lower(),
            ).inc()

            logger.info(
                "notification.delivered",
                notification_id=notification_id,
                notification_type=notification.notification_type.value,
                channel=notification.channel.value,
                is_demo=notification.is_demo,
            )

            return {
                "status": "sent",
                "channel": notification.channel.value,
                "notification_id": notification_id,
            }

        except Exception as exc:
            # Record failure, schedule retry
            notification.retry_count += 1
            notification.failure_reason = str(exc)[:500]
            backoff_seconds = RETRY_BACKOFF_SECONDS.get(notification.retry_count, 480)
            notification.next_retry_at = datetime.now(timezone.utc) + timedelta(
                seconds=backoff_seconds
            )

            if notification.retry_count >= notification.max_retries:
                notification.status = NotificationStatus.FAILED
            # else: remains PENDING for next poll cycle

            await db.commit()
            raise


# ── Channel delivery implementations ─────────────────────────────────────────

async def _deliver_email(notification: Any) -> None:
    """
    Deliver a notification via SendGrid SMTP.

    The email content is rendered from the Jinja2 template matching
    the notification_type. Templates live in notifications/templates/.
    """
    from notifications.dispatcher import dispatch_email  # noqa: PLC0415
    await dispatch_email(notification)


async def _deliver_webhook(notification: Any) -> None:
    """
    Deliver a notification via outbound HTTP POST webhook.

    The webhook payload is HMAC-signed using SERVER_HMAC_KEY so the
    recipient can verify authenticity:
      X-ComplianceLoop-Signature: sha256=<hmac_hex>
    """
    from notifications.dispatcher import dispatch_webhook  # noqa: PLC0415
    await dispatch_webhook(notification)


# ── Gauge update tasks ────────────────────────────────────────────────────────

@app.task(
    name="workers.notification_worker.update_outbox_pending_gauge",
    bind=False,
    queue="notifications",
    ignore_result=True,
)
def update_outbox_pending_gauge() -> None:
    """
    Update the notification_outbox_pending Prometheus gauge.
    Called by Beat every 5 minutes.
    """
    try:
        asyncio.run(_update_outbox_pending_gauge_async())
    except Exception as exc:
        logger.warning("outbox.gauge.update_failed", error=str(exc))


async def _update_outbox_pending_gauge_async() -> None:
    """Count pending notifications and update Prometheus gauge."""
    from db.session import get_session_context  # noqa: PLC0415
    from models.notification_outbox import NotificationOutbox, NotificationStatus  # noqa: PLC0415
    from observability.metrics import NOTIFICATION_OUTBOX_PENDING  # noqa: PLC0415
    from sqlalchemy import func, select  # noqa: PLC0415

    async with get_session_context() as db:
        for is_demo in [False, True]:
            stmt = (
                select(func.count(NotificationOutbox.id))
                .where(
                    NotificationOutbox.status == NotificationStatus.PENDING,
                    NotificationOutbox.is_demo == is_demo,
                )
            )
            result = await db.execute(stmt)
            count = result.scalar_one() or 0
            NOTIFICATION_OUTBOX_PENDING.labels(
                is_demo=str(is_demo).lower()
            ).set(count)


# ── No-op task (Beat schedule placeholder) ───────────────────────────────────

@app.task(
    name="workers.notification_worker.noop_task",
    bind=False,
    queue="calibration",
    ignore_result=True,
)
def noop_task(**kwargs: Any) -> None:
    """
    No-operation task used as a Beat schedule placeholder.
    Used for the nightly-postgres-backup entry (actual backup is host-side cron).
    """
    pass