"""
ComplianceLoop — RetentionEvent Model
=======================================
Audit log of DPDP data retention enforcement wipe events.

Every time the nightly retention_enforcer wipes PII from an application
record (nulling payload_encrypted, clearing PII columns), it creates a
RetentionEvent row recording exactly what was wiped and when.

This provides a compliance audit trail for DPDP's storage limitation
obligation — the NBFC can demonstrate that it enforced retention periods
and when each wipe occurred.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, UUIDPrimaryKeyMixin


class RetentionEvent(UUIDPrimaryKeyMixin, Base):
    """
    Record of a DPDP PII wipe for a single application.

    Immutable — no updates after creation.
    RetentionEvents themselves are retained forever (they contain no PII).
    """

    __tablename__ = "retention_events"
    __table_args__ = (
        Index("ix_retention_events_application_id", "application_id"),
        Index("ix_retention_events_wiped_at", "wiped_at"),
        {"comment": "Audit log of DPDP data retention enforcement wipes"},
    )

    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID_column := __import__(
            "sqlalchemy.dialects.postgresql", fromlist=["UUID"]
        ).UUID(as_uuid=True),
        ForeignKey("applications.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Application whose PII was wiped",
    )

    wiped_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="UTC timestamp when the wipe was executed",
    )

    wipe_task_run_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Celery task ID of the retention_enforcer run that performed this wipe",
    )

    fields_wiped: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment=(
            "Comma-separated list of fields that were nulled. "
            "E.g. 'payload_encrypted,date_of_birth,collateral_value'"
        ),
    )

    retention_policy_days: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="The retention period in days that was enforced (snapshot at wipe time)",
    )

    data_retention_expires_at_snapshot: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="The data_retention_expires_at value that triggered this wipe (snapshot)",
    )

    def __repr__(self) -> str:
        return (
            f"<RetentionEvent id={self.id} "
            f"application_id={self.application_id} "
            f"wiped_at={self.wiped_at}>"
        )