"""
ComplianceLoop — CalibrationConfig Model
==========================================
Versioned threshold configuration for the decision node.

The calibration engine writes a new row here after each nightly run
(never updates — versioned append-only). The pipeline reads the
latest active row at each pipeline execution via:
  SELECT * FROM calibration_config
  WHERE is_active = true
  ORDER BY created_at DESC
  LIMIT 1

This means threshold changes take effect on the next pipeline run
without any code deployment or service restart.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class CalibrationConfig(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Versioned decision threshold configuration.

    Fields that the calibration engine can adjust:
      - approve_threshold: composite_score >= this → APPROVE
      - review_threshold:  composite_score >= this → REVIEW (else REJECT)
      - agent_weights:     per-agent contribution weights (must sum to 1.0)

    All changes are append-only. The engine never UPDATE's this table.
    """

    __tablename__ = "calibration_config"
    __table_args__ = (
        # Only one active config at a time
        Index(
            "ix_calibration_config_active",
            "is_active",
            unique=True,
            postgresql_where=text("is_active = true"),
        ),
        {"comment": "Versioned decision threshold configuration — updated by calibration engine"},
    )

    # ── Decision thresholds ───────────────────────────────────────────────────
    approve_threshold: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.82,
        comment="composite_score >= this → APPROVE. Default: 0.82",
    )

    review_threshold: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.60,
        comment="composite_score >= this (but < approve_threshold) → REVIEW. Default: 0.60",
    )

    # ── Agent weights (must sum to 1.0) ───────────────────────────────────────
    weight_document: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.30,
        comment="Document agent signal weight contribution"
    )

    weight_sanctions: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.25,
        comment="Sanctions agent signal weight contribution"
    )

    weight_temporal: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.20,
        comment="Temporal agent signal weight contribution"
    )

    weight_transaction: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.20,
        comment="Transaction agent signal weight contribution"
    )

    weight_rag: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.05,
        comment="RAG agent signal weight contribution (context enrichment only)"
    )

    # ── Version metadata ──────────────────────────────────────────────────────
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment="True = this config is used by the pipeline. Only one can be active.",
    )

    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        comment="Sequential version number — incremented by calibration engine",
    )

    adjustment_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment=(
            "Human-readable reason for this adjustment. "
            "E.g. 'Override rate 42% in 0.60-0.65 band; nudged review_threshold down by 0.03'"
        ),
    )

    samples_analysed: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Number of reviewer feedback records analysed in this calibration cycle",
    )

    previous_config_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        comment="UUID of the CalibrationConfig this version replaced",
    )

    def __repr__(self) -> str:
        return (
            f"<CalibrationConfig v{self.version_number} "
            f"approve={self.approve_threshold} "
            f"review={self.review_threshold} "
            f"active={self.is_active}>"
        )