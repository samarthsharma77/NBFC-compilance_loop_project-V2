"""
ComplianceLoop — NotificationOutbox Model
==========================================
Implements the Transactional Outbox Pattern for reliable notification delivery.

Why transactional outbox?
  When a retro-eval run changes a decision, we need to:
    1. Write the new Decision record
    2. Write the new AuditRecord
    3. Send notifications to applicant and reviewer

  If we send notifications directly after writing to the DB, a crash between
  steps 2 and 3 means notifications are never sent. Conversely, if we send
  first and then crash, we have sent notifications for a write that didn't
  complete.

  The transactional outbox solves this: notification rows are written in the
  SAME database transaction as the Decision and AuditRecord. The notification
  worker then polls this table and delivers pending notifications. Even if the
  worker crashes mid-delivery, the row stays PENDING and is retried on next poll.

  This gives us at-least-once delivery semantics for all notifications.

Notification types:
  - DECISION_CHANGE : Retro-eval changed a prior decision (applicant + reviewer)
  - REVIEW_ASSIGNED : New REVIEW case added to reviewer queue
  - BREACH_ALERT    : DPDP data breach detected (applicant + DPDP Board)

Channels:
  - EMAIL   : SendGrid SMTP
  - WEBHOOK : Outbound HTTP POST with HMAC signature
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import enum

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, IsDemoMixin, TimestampMixin, UUIDPrimaryKeyMixin


class NotificationType(str, enum.Enum):
    DECISION_CHANGE = "DECISION_CHANGE"
    REVIEW_ASSIGNED = "REVIEW_ASSIGNED"
    BREACH_ALERT = "BREACH_ALERT"


class NotificationChannel(str, enum.Enum):
    EMAIL = "EMAIL"
    WEBHOOK = "WEBHOOK"


class NotificationStatus(str, enum.Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    SUPPRESSED = "SUPPRESSED"   # Intentionally not sent (e.g. demo suppression rule)


class NotificationOutbox(UUIDPrimaryKeyMixin, TimestampMixin, IsDemoMixin, Base):
    """
    Outbox row for a single notification to be delivered.

    The notification worker polls:
      SELECT * FROM notification_outbox
      WHERE status = 'PENDING'
      AND (next_retry_at IS NULL OR next_retry_at <= NOW())
      ORDER BY created_at ASC
      LIMIT 100
      FOR UPDATE SKIP LOCKED   ← prevents two workers picking same row
    """

    __tablename__ = "notification_outbox"
    __table_args__ = (
        # Worker polling query
        Index(
            "ix_notification_outbox_pending",
            "status",
            "next_retry_at",
            postgresql_where=text("status = 'PENDING'"),
        ),
        # Lookup notifications for a specific application (admin queries)
        Index("ix_notification_outbox_application", "recipient_application_id"),
        {"comment": "Transactional outbox for at-least-once notification delivery"},
    )

    # ── Notification type & channel ───────────────────────────────────────────
    notification_type: Mapped[NotificationType] = mapped_column(
        Enum(NotificationType, name="notification_type_enum", create_type=True),
        nullable=False,
        index=True,
        comment="Type of notification being sent",
    )

    channel: Mapped[NotificationChannel] = mapped_column(
        Enum(NotificationChannel, name="notification_channel_enum", create_type=True),
        nullable=False,
        comment="Delivery channel: EMAIL or WEBHOOK",
    )

    # ── Recipients ────────────────────────────────────────────────────────────
    recipient_application_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("applications.id", ondelete="SET NULL"),
        nullable=True,
        comment="Application whose applicant is being notified — NULL for reviewer-only notifications",
    )

    recipient_reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("reviewers.id", ondelete="SET NULL"),
        nullable=True,
        comment="Reviewer being notified — NULL for applicant-only notifications",
    )

    recipient_email: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Direct email address — populated at creation time so delivery works even if reviewer is deleted",
    )

    recipient_webhook_url: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Webhook URL — populated at creation time",
    )

    # ── Payload ───────────────────────────────────────────────────────────────
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Full notification payload. For DECISION_CHANGE: "
            "{old_outcome, new_outcome, old_confidence, new_confidence, "
            "guideline_diff_summary, circular_reference, audit_trail_url}"
        ),
    )

    # ── Delivery status ───────────────────────────────────────────────────────
    status: Mapped[NotificationStatus] = mapped_column(
        Enum(NotificationStatus, name="notification_status_enum", create_type=True),
        nullable=False,
        default=NotificationStatus.PENDING,
        server_default=text("'PENDING'"),
        index=True,
        comment="Delivery status — PENDING until worker delivers or exhausts retries",
    )

    retry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
        comment="Number of delivery attempts made",
    )

    max_retries: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
        server_default=text("3"),
        comment="Maximum delivery attempts before marking FAILED",
    )

    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp of next retry attempt — NULL means eligible for immediate delivery",
    )

    sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp of successful delivery",
    )

    failure_reason: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Last error message from failed delivery attempt",
    )

    def __repr__(self) -> str:
        return (
            f"<NotificationOutbox id={self.id} "
            f"type={self.notification_type} "
            f"channel={self.channel} "
            f"status={self.status}>"
        )