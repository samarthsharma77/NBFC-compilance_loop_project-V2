"""
ComplianceLoop — ConsentVersion Model
=======================================
Tracks versions of the DPDP consent form shown to applicants.

When the NBFC updates its consent language (e.g. to reflect new DPDP Rules),
a new ConsentVersion row is created and set as active. All subsequent
applications must reference the new version — applications with stale
consent_version strings are rejected at the API middleware layer.

This ensures the NBFC can demonstrate that every applicant consented to
the current version of the data processing notice, satisfying DPDP's
notice and consent obligations.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ConsentVersion(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    A version of the DPDP consent form/notice.
    """

    __tablename__ = "consent_versions"
    __table_args__ = (
        Index(
            "ix_consent_versions_active",
            "is_active",
            unique=True,
            postgresql_where=text("is_active = true"),
        ),
        Index("ix_consent_versions_version_id", "version_id", unique=True),
        {"comment": "DPDP consent form versions — applicants must reference the active version"},
    )

    version_id: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        unique=True,
        comment="Human-readable version identifier. E.g. 'v1.0', 'v1.1-dpdp-rules-2025'",
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Short title of this consent version",
    )

    consent_text: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Full text of the consent notice shown to applicants",
    )

    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Plain-language summary of what data is collected and why",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment="True = this is the current consent version. Only one can be active.",
    )

    effective_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="UTC timestamp from which this consent version is required",
    )

    superseded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when this version was replaced by a newer one",
    )

    change_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Summary of what changed from the prior version — for internal audit",
    )

    def __repr__(self) -> str:
        return (
            f"<ConsentVersion version_id={self.version_id!r} active={self.is_active}>"
        )