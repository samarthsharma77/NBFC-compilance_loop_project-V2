"""
ComplianceLoop — AuditRecord Model
=====================================
Immutable audit ledger. One row per pipeline run (per Decision).

Critical properties:
  - Written BEFORE the API response is returned (pre-response audit write)
  - agent_outputs_hash: SHA-256 of canonical JSON of all 5 AgentResults
  - record_hmac: HMAC-SHA256 binding hash + decision metadata + server secret
  - affected_agent_tags: GIN-indexed TEXT[] — the key field enabling the
    optimised retro-eval filter query (array overlap operator &&)
  - payload_s3_key: MinIO object key for long-term encrypted payload storage

The affected_agent_tags array is inherited from the GuidelineVersion used
in the pipeline run. It encodes WHICH compliance agents the guideline version
affects. This allows the retro-eval filter to ask:
  "Which past decisions used a guideline version that affected the 'temporal' agent?"
  → SELECT DISTINCT application_id FROM audit_records
    WHERE guideline_version_id = :old_version
    AND affected_agent_tags && ARRAY['temporal']

This query uses the GIN index and returns results in <100ms on 1M rows.
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
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import Base, IsDemoMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from models.decision import Decision


class AuditRecord(UUIDPrimaryKeyMixin, IsDemoMixin, Base):
    """
    Tamper-evident audit record written before API responds.

    NOT using TimestampMixin because:
      - written_at is set explicitly by audit/writer.py (not automatically)
      - There is no updated_at — audit records are immutable
      - We need precise control over the written_at value for HMAC computation

    Immutability contract:
      - No UPDATE statements should ever touch this table in application code
      - The only legitimate mutation is breach_flag = True via the break_glass procedure
      - Alembic migrations must never DROP or ALTER columns on this table
        without creating a new migration that preserves existing data
    """

    __tablename__ = "audit_records"
    __table_args__ = (
        # CRITICAL: Uniqueness — one audit record per decision run
        UniqueConstraint("decision_id", name="uq_audit_records_decision_id"),
        # Primary retro-eval filter query:
        # WHERE guideline_version_id = :v AND affected_agent_tags && ARRAY[...]
        # GIN index on the array column enables the && operator efficiently
        Index(
            "ix_audit_records_agent_tags_gin",
            "affected_agent_tags",
            postgresql_using="gin",
        ),
        # Composite index for retro-eval: version + tags query
        Index(
            "ix_audit_records_version_tags",
            "guideline_version_id",
            "application_id",
        ),
        # application_id index for decision history lookups
        Index("ix_audit_records_application_id", "application_id"),
        # written_at index for time-range audit queries
        Index("ix_audit_records_written_at", "written_at"),
        {"comment": "Immutable tamper-evident audit ledger — one row per pipeline run"},
    )

    # ── Foreign keys ──────────────────────────────────────────────────────────
    decision_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("decisions.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
        comment="Decision this audit record covers — UNIQUE (one record per decision)",
    )

    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("applications.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Application this record covers — indexed for retro-eval queries",
    )

    guideline_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guideline_versions.id", ondelete="RESTRICT"),
        nullable=False,
        comment="GuidelineVersion used in the pipeline run that produced this record",
    )

    # ── Retro-eval tag array (GIN-indexed) ────────────────────────────────────
    affected_agent_tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(50)),
        nullable=False,
        default=list,
        comment=(
            "Array of agent names affected by the guideline_version used. "
            "E.g. ['temporal', 'transaction']. "
            "GIN-indexed — enables efficient && (array overlap) queries for retro-eval filter. "
            "Inherited from GuidelineVersion.affected_agent_tags at write time."
        ),
    )

    # ── Integrity fields ──────────────────────────────────────────────────────
    agent_outputs_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment=(
            "SHA-256 hex digest of canonical JSON of all five AgentResult objects. "
            "Recompute and compare to verify content integrity."
        ),
    )

    record_hmac: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment=(
            "HMAC-SHA256(agent_outputs_hash|decision_id|guideline_version_id|written_at, SERVER_HMAC_KEY). "
            "Pipe-separated message. Verifies authenticity — proves record was signed by this server."
        ),
    )

    # ── MinIO payload reference ───────────────────────────────────────────────
    payload_s3_key: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment=(
            "MinIO object key for the AES-256-GCM encrypted full payload. "
            "Format: audit/{year}/{month}/{decision_id}.json.enc. "
            "NULL if MinIO upload is pending or failed (Postgres record is source of truth)."
        ),
    )

    payload_s3_uploaded: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment="True once the MinIO upload completes successfully",
    )

    # ── Timestamp ─────────────────────────────────────────────────────────────
    written_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment=(
            "UTC timestamp when this audit record was written. "
            "Set by server — used in HMAC computation. "
            "Written BEFORE API response is returned."
        ),
    )

    # ── Breach response ───────────────────────────────────────────────────────
    breach_flag: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment=(
            "Set to True by break_glass procedure on DPDP data breach. "
            "Triggers notification to affected applicant and DPDP Board report."
        ),
    )

    breach_flagged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when breach_flag was set",
    )

    # ── Relationship ──────────────────────────────────────────────────────────
    decision: Mapped[Decision] = relationship(
        "Decision",
        back_populates="audit_record",
    )

    def __repr__(self) -> str:
        return (
            f"<AuditRecord id={self.id} "
            f"decision_id={self.decision_id} "
            f"tags={self.affected_agent_tags} "
            f"breach={self.breach_flag}>"
        )