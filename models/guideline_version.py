"""
ComplianceLoop — GuidelineVersion Model
=========================================
Represents a versioned snapshot of a regulatory circular or guideline.

One row per scraped version of each circular. The active version for a
given circular_reference is the one with is_active=True.

The parameters JSONB column stores the structured rule parameters that
the pipeline agents read at runtime — FOIR limits, NTH thresholds,
KYC intervals, etc. This is what allows regulatory changes to take effect
without code deployment.

The affected_agent_tags TEXT[] tells the retro-eval system which agents
are affected by this version's rules. This is the critical link between
guideline changes and the optimised retro-eval filter query.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import Base, IsDemoMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from models.decision import Decision


class GuidelineVersion(UUIDPrimaryKeyMixin, TimestampMixin, IsDemoMixin, Base):
    """
    A versioned regulatory guideline or circular.

    Scraped by the regulatory intelligence subsystem. Each new version
    of a circular creates a new row — prior versions are never deleted
    (audit records reference them by FK).

    Only one version per circular_reference can be active at a time.
    The partial unique index enforces this at the DB level.
    """

    __tablename__ = "guideline_versions"
    __table_args__ = (
        # Only one active version per circular reference per environment
        UniqueConstraint(
            "circular_reference",
            "is_active",
            "is_demo",
            name="uq_guideline_active_per_circular",
            # PostgreSQL partial unique constraint — only enforces uniqueness
            # when is_active=True. Multiple inactive versions are allowed.
            # NOTE: This is enforced in application logic; SQLAlchemy UniqueConstraint
            # doesn't support partial — the partial index below handles it.
        ),
        # Partial unique index: only one is_active=True per circular_reference
        Index(
            "ix_guideline_versions_active_circular",
            "circular_reference",
            "is_demo",
            unique=True,
            postgresql_where=text("is_active = true"),
        ),
        # GIN index on affected_agent_tags for retro-eval tagger queries
        Index(
            "ix_guideline_versions_agent_tags_gin",
            "affected_agent_tags",
            postgresql_using="gin",
        ),
        # Lookup by circular reference (scraper dedup check)
        Index("ix_guideline_versions_circular_ref", "circular_reference"),
        {"comment": "Versioned regulatory guidelines scraped from RBI and DPDP sources"},
    )

    # ── Source information ────────────────────────────────────────────────────
    source_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="URL of the scraped circular/direction page",
    )

    circular_reference: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment=(
            "RBI circular reference number. "
            "E.g. RBI/2024-25/73 DNBR.CC.PD.No.141/03.10.001/2024-25"
        ),
    )

    title: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable title of the circular",
    )

    # ── Dates ─────────────────────────────────────────────────────────────────
    effective_date: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
        comment="Date from which this circular's rules take effect",
    )

    sunset_date: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
        comment="Date this circular is superseded (if specified). NULL = no known sunset.",
    )

    scraped_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="UTC timestamp when this version was scraped",
    )

    # ── Content fingerprint ───────────────────────────────────────────────────
    content_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment=(
            "SHA-256 of the full circular text body. "
            "Used by delta detector to identify changes."
        ),
    )

    diff_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment=(
            "Human-readable summary of what changed from the prior version. "
            "E.g. 'Section 4.2: FOIR limit changed from 55% to 50% for unsecured loans'. "
            "NULL for first version of a circular."
        ),
    )

    # ── Agent tagging ─────────────────────────────────────────────────────────
    affected_agent_tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(50)),
        nullable=False,
        default=list,
        comment=(
            "Which pipeline agents are affected by this guideline. "
            "E.g. ['transaction'] for FOIR change, ['temporal', 'document'] for KYC change. "
            "GIN-indexed. Used by retro-eval filter to identify affected past decisions."
        ),
    )

    # ── Rule parameters (read by pipeline agents at runtime) ─────────────────
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment=(
            "Structured rule parameters for this guideline version. "
            "Read by pipeline agents — changes here take effect without code deployment. "
            "Example: {"
            "  'foir_threshold_unsecured': 0.50, "
            "  'foir_threshold_secured': 0.65, "
            "  'kyc_update_interval_low_risk_years': 10, "
            "  'kyc_update_interval_medium_risk_years': 8, "
            "  'kyc_update_interval_high_risk_years': 2, "
            "  'nth_threshold_tier1': 15000, "
            "  'nth_threshold_tier2': 10000, "
            "  'nth_threshold_tier3': 7500, "
            "  'ltv_residential': 0.75, "
            "  'bureau_report_max_age_days': 30, "
            "  'vcip_validity_months': 6, "
            "  'cooling_period_days': 60 "
            "}"
        ),
    )

    # ── Activation status ─────────────────────────────────────────────────────
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment=(
            "True = this version is currently used by the pipeline. "
            "Only one version per circular_reference per environment can be active. "
            "Enforced by partial unique index."
        ),
    )

    promoted_by: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment=(
            "Identifier of reviewer who activated this version. "
            "NULL = auto-promoted (demo mode or first version)."
        ),
    )

    promoted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when is_active was set to True",
    )

    # ── Raw content ───────────────────────────────────────────────────────────
    raw_content_s3_key: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="MinIO key for the raw HTML/PDF of this circular — for audit reference",
    )

    def __repr__(self) -> str:
        return (
            f"<GuidelineVersion id={self.id} "
            f"ref={self.circular_reference!r} "
            f"active={self.is_active} "
            f"tags={self.affected_agent_tags}>"
        )