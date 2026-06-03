"""
ComplianceLoop — Reviewer & ReviewerFeedback Models
======================================================
Two models:
  - Reviewer: Human compliance reviewer who handles REVIEW queue cases
  - ReviewerFeedback: Outcome recorded when reviewer acts on a REVIEW decision

ReviewerFeedback feeds the calibration engine. The four outcome types are:
  - CONFIRM_APPROVE : Reviewer agrees the case should be approved
  - CONFIRM_REJECT  : Reviewer agrees the case should be rejected
  - OVERRIDE_APPROVE: Reviewer approves a case pipeline sent to REVIEW
  - OVERRIDE_REJECT : Reviewer rejects a case pipeline sent to REVIEW

The calibration engine groups feedback by the pipeline's confidence score
band at the time of the REVIEW decision, and uses the override rate to
nudge the APPROVE/REVIEW threshold up or down.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import enum

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import Base, IsDemoMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from models.decision import Decision


class ReviewerRole(str, enum.Enum):
    REVIEWER = "REVIEWER"
    SENIOR_REVIEWER = "SENIOR_REVIEWER"
    COMPLIANCE_ADMIN = "COMPLIANCE_ADMIN"


class ReviewerOutcome(str, enum.Enum):
    CONFIRM_APPROVE = "CONFIRM_APPROVE"
    CONFIRM_REJECT = "CONFIRM_REJECT"
    OVERRIDE_APPROVE = "OVERRIDE_APPROVE"
    OVERRIDE_REJECT = "OVERRIDE_REJECT"
    ESCALATE = "ESCALATE"       # Escalate to senior reviewer


class Reviewer(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    A human compliance reviewer who handles REVIEW queue cases.

    Not using IsDemoMixin — reviewer accounts are shared infrastructure,
    but their feedback rows carry the is_demo flag from the decision they act on.
    """

    __tablename__ = "reviewers"
    __table_args__ = (
        Index("ix_reviewers_email", "email", unique=True),
        {"comment": "Human compliance reviewers who act on REVIEW queue cases"},
    )

    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        comment="Reviewer email address — used for notifications",
    )

    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Reviewer full name",
    )

    role: Mapped[ReviewerRole] = mapped_column(
        Enum(ReviewerRole, name="reviewer_role_enum", create_type=True),
        nullable=False,
        default=ReviewerRole.REVIEWER,
        comment="Reviewer role — determines access level and queue visibility",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
        comment="False = reviewer deactivated (off-boarded)",
    )

    notification_webhook_url: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Optional webhook URL to receive REVIEW_ASSIGNED notifications",
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    feedback: Mapped[list[ReviewerFeedback]] = relationship(
        "ReviewerFeedback",
        back_populates="reviewer",
    )

    def __repr__(self) -> str:
        return f"<Reviewer id={self.id} email={self.email!r} role={self.role}>"


class ReviewerFeedback(UUIDPrimaryKeyMixin, TimestampMixin, IsDemoMixin, Base):
    """
    Outcome recorded when a reviewer acts on a REVIEW decision.

    This is the primary input to the calibration engine. The engine
    groups these records by the pipeline decision's confidence band
    and computes override rates to adjust thresholds.
    """

    __tablename__ = "reviewer_feedback"
    __table_args__ = (
        # Calibration engine: feedback by decision confidence band and date range
        Index("ix_reviewer_feedback_created_at", "created_at"),
        # Lookup feedback for a specific decision
        Index("ix_reviewer_feedback_decision_id", "decision_id"),
        # Reviewer activity report
        Index("ix_reviewer_feedback_reviewer_id", "reviewer_id"),
        {"comment": "Reviewer outcomes on REVIEW decisions — feeds calibration engine"},
    )

    # ── Foreign keys ──────────────────────────────────────────────────────────
    decision_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("decisions.id", ondelete="RESTRICT"),
        nullable=False,
        comment="The REVIEW decision being acted upon",
    )

    reviewer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("reviewers.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Reviewer who submitted this feedback",
    )

    # ── Outcome ───────────────────────────────────────────────────────────────
    reviewer_outcome: Mapped[ReviewerOutcome] = mapped_column(
        Enum(ReviewerOutcome, name="reviewer_outcome_enum", create_type=True),
        nullable=False,
        index=True,
        comment=(
            "Reviewer decision: CONFIRM_APPROVE, CONFIRM_REJECT, "
            "OVERRIDE_APPROVE, OVERRIDE_REJECT, or ESCALATE"
        ),
    )

    reviewer_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional reviewer notes explaining the decision — used in calibration analysis",
    )

    # ── Snapshot of pipeline confidence at review time ────────────────────────
    # Denormalised here so calibration queries don't need to JOIN decisions
    pipeline_confidence_at_review: Mapped[float | None] = mapped_column(
        nullable=True,
        comment=(
            "Decision.confidence value at time of review — denormalised for "
            "calibration engine queries (avoids JOIN to decisions table)"
        ),
    )

    review_duration_seconds: Mapped[int | None] = mapped_column(
        nullable=True,
        comment="How long the reviewer spent on this case (from queue open to submission)",
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    decision: Mapped[Decision] = relationship(
        "Decision",
        back_populates="reviewer_feedback",
    )

    reviewer: Mapped[Reviewer] = relationship(
        "Reviewer",
        back_populates="feedback",
    )

    def __repr__(self) -> str:
        return (
            f"<ReviewerFeedback id={self.id} "
            f"decision_id={self.decision_id} "
            f"outcome={self.reviewer_outcome}>"
        )