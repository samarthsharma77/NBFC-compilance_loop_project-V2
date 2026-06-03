"""
ComplianceLoop — Application Model
=====================================
Represents a single loan application submitted to the compliance pipeline.

Key design decisions:
  - PAN is stored only as pan_hmac (HMAC-SHA256). Plaintext PAN is discarded
    at ingestion by security/pan_handler.py. NEVER stored here.
  - payload_encrypted stores the full application payload as AES-256-GCM
    encrypted bytes. Nulled out after data_retention_expires_at passes.
  - DPDP consent fields are NOT NULL — application cannot exist without consent.
  - guideline_version_id captures which version of regulations was active when
    the application was SUBMITTED (not when it was evaluated — the evaluation
    may happen under a newer version if re-eval is triggered).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import Base, IsDemoMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from models.decision import Decision
    from models.guideline_version import GuidelineVersion


class Application(UUIDPrimaryKeyMixin, TimestampMixin, IsDemoMixin, Base):
    """
    Loan application submitted to the ComplianceLoop pipeline.

    Lifecycle:
      1. Created at ingestion (POST /v1/applications)
      2. payload_encrypted holds full PII payload until retention_wiped
      3. After data_retention_expires_at: payload_encrypted → NULL,
         PII columns → NULL, retention_wiped → True
      4. UUID and pan_hmac remain forever (needed for audit trail linkage)
    """

    __tablename__ = "applications"
    __table_args__ = (
        # Composite index for DPDP retention enforcement query
        Index("ix_applications_retention_wipe", "data_retention_expires_at", "retention_wiped"),
        # Index for applicant lookups by pan_hmac (sanctions re-check)
        Index("ix_applications_pan_hmac", "pan_hmac"),
        # Partial index — active (not wiped) applications only
        Index(
            "ix_applications_active_demo",
            "is_demo",
            "submitted_at",
            postgresql_where=text("retention_wiped = false"),
        ),
        {"comment": "Loan applications submitted to the compliance pipeline"},
    )

    # ── Applicant identifiers ─────────────────────────────────────────────────
    applicant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="External applicant identifier provided by the NBFC client system",
    )

    applicant_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Normalised applicant name (uppercased, trimmed) — used for sanctions fuzzy match",
    )

    pan_hmac: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="HMAC-SHA256 of PAN using PAN_HMAC_KEY. Plaintext PAN never stored.",
    )

    pan_format_valid: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether PAN passed format validation at ingestion time",
    )

    # ── Loan details ──────────────────────────────────────────────────────────
    loan_amount_requested: Mapped[float] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        comment="Requested loan amount in Indian Rupees",
    )

    loan_tenure_months: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Requested loan tenure in months",
    )

    loan_purpose: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment=(
            "Loan purpose taxonomy code. "
            "E.g. PERSONAL_UNSECURED, HOME_SECURED, VEHICLE_SECURED, BUSINESS_UNSECURED"
        ),
    )

    declared_income: Mapped[float] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        comment="Declared gross monthly income in INR",
    )

    declared_obligations: Mapped[float] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0.0,
        comment="Declared existing monthly EMI obligations in INR",
    )

    collateral_value: Mapped[float | None] = mapped_column(
        Numeric(15, 2),
        nullable=True,
        comment="Declared collateral value in INR — only for secured loans",
    )

    city_tier: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True,
        comment="City tier for NTH threshold: TIER_1, TIER_2, TIER_3",
    )

    # ── Onboarding flags ──────────────────────────────────────────────────────
    remote_onboarding: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment="True if applicant was onboarded remotely via V-CIP",
    )

    applicant_risk_category: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="LOW",
        comment="RBI KYC risk category: LOW, MEDIUM, HIGH",
    )

    # ── Guideline version at submission ───────────────────────────────────────
    guideline_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guideline_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Active GuidelineVersion at time of submission — may differ from evaluation version",
    )

    # ── Encrypted payload (full PII) ──────────────────────────────────────────
    payload_encrypted: Mapped[bytes | None] = mapped_column(
        nullable=True,
        comment=(
            "AES-256-GCM encrypted full application payload including all PII. "
            "Set to NULL after data_retention_expires_at by retention_enforcer."
        ),
    )

    # ── DPDP consent ──────────────────────────────────────────────────────────
    dpdp_consent_given: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        comment="DPDP consent was obtained — hard gate at API layer",
    )

    dpdp_consent_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Version of consent form accepted (references consent_versions.version_id)",
    )

    dpdp_consent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="UTC timestamp when consent was given by applicant",
    )

    # ── DPDP retention ────────────────────────────────────────────────────────
    data_retention_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment=(
            "UTC timestamp after which payload_encrypted and PII fields are wiped. "
            "Set at ingestion. Default: 90 days after final decision."
        ),
    )

    retention_wiped: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment="True after nightly retention_enforcer has wiped PII from this record",
    )

    retention_wiped_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when retention wipe was executed",
    )

    # ── Submission metadata ───────────────────────────────────────────────────
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="UTC timestamp of API receipt — set by server, not client",
    )

    source_ip_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="SHA-256 of client IP — for audit purposes, not PII",
    )

    api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("api_keys.id", ondelete="SET NULL"),
        nullable=True,
        comment="Which API key submitted this application",
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    decisions: Mapped[list[Decision]] = relationship(
        "Decision",
        back_populates="application",
        order_by="Decision.run_number",
        cascade="all, delete-orphan",
    )

    guideline_version: Mapped[GuidelineVersion | None] = relationship(
        "GuidelineVersion",
        foreign_keys=[guideline_version_id],
    )

    def __repr__(self) -> str:
        return (
            f"<Application id={self.id} "
            f"applicant_id={self.applicant_id} "
            f"loan={self.loan_amount_requested} "
            f"is_demo={self.is_demo}>"
        )