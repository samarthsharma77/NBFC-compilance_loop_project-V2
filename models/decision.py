"""
ComplianceLoop — Decision Model
=================================
Represents a single pipeline run result for an application.

Key points:
  - run_number=1 is the original decision
  - run_number>=2 are retro-eval runs triggered by guideline changes
  - previous_decision_id links re-eval runs to their predecessor
  - agent_outputs JSONB stores the full AgentResult for all 5 agents
  - rationale_chain JSONB stores the ordered list of RationaleEntry objects
  - guideline_version_id here is the version used for THIS run specifically
    (may differ from application.guideline_version_id)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import Base, IsDemoMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from models.application import Application
    from models.audit_record import AuditRecord
    from models.guideline_version import GuidelineVersion
    from models.reviewer import ReviewerFeedback

import enum


class DecisionOutcome(str, enum.Enum):
    APPROVE = "APPROVE"
    REVIEW = "REVIEW"
    REJECT = "REJECT"


class Decision(UUIDPrimaryKeyMixin, TimestampMixin, IsDemoMixin, Base):
    """
    Result of a single compliance pipeline run for an application.

    One application can have multiple Decision rows:
      - run_number=1: original decision
      - run_number=2+: retro-eval runs after guideline changes

    The full decision chain is queryable via:
      SELECT * FROM decisions
      WHERE application_id = :id
      ORDER BY run_number ASC
    """

    __tablename__ = "decisions"
    __table_args__ = (
        # Primary lookup: all decisions for an application in run order
        Index("ix_decisions_application_run", "application_id", "run_number"),
        # Retro-eval queries: find all decisions under a specific guideline version
        Index("ix_decisions_guideline_version", "guideline_version_id", "outcome"),
        # Calibration engine queries: reviewer feedback needs REVIEW outcomes
        Index(
            "ix_decisions_review_outcomes",
            "outcome",
            "created_at",
            postgresql_where=text("outcome = 'REVIEW'"),
        ),
        # Demo filtering
        Index("ix_decisions_is_demo", "is_demo", "created_at"),
        {"comment": "Pipeline run results — one row per evaluation of an application"},
    )

    # ── Foreign keys ──────────────────────────────────────────────────────────
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("applications.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Application this decision belongs to",
    )

    guideline_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guideline_versions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="GuidelineVersion used in THIS specific pipeline run",
    )

    previous_decision_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("decisions.id", ondelete="SET NULL"),
        nullable=True,
        comment="ID of prior decision — NULL for run_number=1, set for retro-eval runs",
    )

    # ── Run metadata ──────────────────────────────────────────────────────────
    run_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        comment="1 = original decision; 2+ = retro-evaluation run number",
    )

    is_retro_eval: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment="True if this decision was produced by the retro-eval loop",
    )

    # ── Outcome ───────────────────────────────────────────────────────────────
    outcome: Mapped[DecisionOutcome] = mapped_column(
        Enum(DecisionOutcome, name="decision_outcome_enum", create_type=True),
        nullable=False,
        index=True,
        comment="Pipeline decision: APPROVE, REVIEW, or REJECT",
    )

    confidence: Mapped[float] = mapped_column(
        Numeric(5, 4),
        nullable=False,
        comment="Decision confidence score 0.0000–1.0000. Near 0.5 = near threshold boundary.",
    )

    composite_score: Mapped[float] = mapped_column(
        Numeric(5, 4),
        nullable=False,
        comment="Weighted aggregate of agent signal_weights before threshold application",
    )

    # ── Agent outputs (full detail for audit & explainability) ────────────────
    agent_outputs: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Full AgentResult for all 5 agents: "
            "{document: {...}, sanctions: {...}, temporal: {...}, transaction: {...}, rag: {...}}"
        ),
    )

    outcome_signals: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Per-agent signal weight and composite contribution: "
            "{document: {weight: 0.30, signal: 0.85, contribution: 0.255}, ...}"
        ),
    )

    rationale_chain: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Ordered list of RationaleEntry objects — human-readable explanation "
            "of each agent's contribution to the decision"
        ),
    )

    # ── Performance ───────────────────────────────────────────────────────────
    pipeline_duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="End-to-end pipeline execution time in milliseconds",
    )

    # ── Timestamps ────────────────────────────────────────────────────────────
    # Note: created_at from TimestampMixin serves as the decision timestamp.
    # We do not add a separate decided_at — created_at IS the decision time.

    # ── Relationships ─────────────────────────────────────────────────────────
    application: Mapped[Application] = relationship(
        "Application",
        back_populates="decisions",
    )

    guideline_version: Mapped[GuidelineVersion] = relationship(
        "GuidelineVersion",
        foreign_keys=[guideline_version_id],
    )

    previous_decision: Mapped[Decision | None] = relationship(
        "Decision",
        remote_side="Decision.id",
        foreign_keys=[previous_decision_id],
    )

    audit_record: Mapped[AuditRecord | None] = relationship(
        "AuditRecord",
        back_populates="decision",
        uselist=False,
    )

    reviewer_feedback: Mapped[list[ReviewerFeedback]] = relationship(
        "ReviewerFeedback",
        back_populates="decision",
    )

    def __repr__(self) -> str:
        return (
            f"<Decision id={self.id} "
            f"application_id={self.application_id} "
            f"run={self.run_number} "
            f"outcome={self.outcome} "
            f"confidence={self.confidence}>"
        )