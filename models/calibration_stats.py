"""
ComplianceLoop — CalibrationStats Model
=========================================
Rolling statistics written by the calibration engine each nightly run.
Read by Prometheus scraper and Grafana for the Calibration Tracker dashboard.

One row per calibration cycle. Prometheus scrapes the latest row's values
via the /v1/calibration/status endpoint which exposes them as Gauges.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class CalibrationStats(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Statistics from a single calibration engine run.
    Used by Grafana Calibration Tracker dashboard and Prometheus confidence drift alert.
    """

    __tablename__ = "calibration_stats"
    __table_args__ = (
        Index("ix_calibration_stats_created_at", "created_at"),
        {"comment": "Nightly calibration run statistics — read by Prometheus and Grafana"},
    )

    # ── Decision distribution (last 7 days) ───────────────────────────────────
    total_decisions_7d: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Total pipeline runs in last 7 days",
    )

    approve_count_7d: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="APPROVE decisions in last 7 days",
    )

    review_count_7d: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="REVIEW decisions in last 7 days",
    )

    reject_count_7d: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="REJECT decisions in last 7 days",
    )

    # ── Confidence distribution ───────────────────────────────────────────────
    confidence_mean_7d: Mapped[float | None] = mapped_column(
        Float, nullable=True,
        comment="7-day rolling mean of confidence scores",
    )

    confidence_stddev_7d: Mapped[float | None] = mapped_column(
        Float, nullable=True,
        comment=(
            "7-day rolling standard deviation of confidence scores. "
            "Alert fires if this exceeds 0.15 (confidence drift)."
        ),
    )

    confidence_p50_7d: Mapped[float | None] = mapped_column(
        Float, nullable=True, comment="50th percentile confidence score"
    )

    confidence_p95_7d: Mapped[float | None] = mapped_column(
        Float, nullable=True, comment="95th percentile confidence score"
    )

    # ── Override rates by confidence band ─────────────────────────────────────
    # Stored as JSON-encoded dict in a float column would be messy;
    # storing pre-computed summary rates for the bands the calibration engine tracks
    override_rate_band_060_065: Mapped[float | None] = mapped_column(
        Float, nullable=True, comment="Override rate for confidence band 0.60-0.65"
    )

    override_rate_band_065_070: Mapped[float | None] = mapped_column(
        Float, nullable=True, comment="Override rate for confidence band 0.65-0.70"
    )

    override_rate_band_070_075: Mapped[float | None] = mapped_column(
        Float, nullable=True, comment="Override rate for confidence band 0.70-0.75"
    )

    override_rate_band_075_080: Mapped[float | None] = mapped_column(
        Float, nullable=True, comment="Override rate for confidence band 0.75-0.80"
    )

    override_rate_band_080_085: Mapped[float | None] = mapped_column(
        Float, nullable=True, comment="Override rate for confidence band 0.80-0.85"
    )

    # ── Reviewer activity ─────────────────────────────────────────────────────
    total_feedback_30d: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Total reviewer feedback records in last 30 days",
    )

    override_approve_30d: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="OVERRIDE_APPROVE count in last 30 days",
    )

    override_reject_30d: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="OVERRIDE_REJECT count in last 30 days",
    )

    # ── Threshold snapshot ────────────────────────────────────────────────────
    approve_threshold_snapshot: Mapped[float | None] = mapped_column(
        Float, nullable=True,
        comment="approve_threshold value at time of this stats run",
    )

    review_threshold_snapshot: Mapped[float | None] = mapped_column(
        Float, nullable=True,
        comment="review_threshold value at time of this stats run",
    )

    # ── Run metadata ──────────────────────────────────────────────────────────
    run_duration_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="How long the calibration engine took to run",
    )

    def __repr__(self) -> str:
        return (
            f"<CalibrationStats "
            f"mean={self.confidence_mean_7d} "
            f"stddev={self.confidence_stddev_7d} "
            f"total={self.total_decisions_7d}>"
        )