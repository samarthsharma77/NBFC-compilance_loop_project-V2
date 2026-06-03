"""
ComplianceLoop — APIKey Model
================================
Stores hashed API keys used to authenticate requests to the ComplianceLoop API.

API key plaintext is NEVER stored. Only the bcrypt hash is stored.
The plaintext key is shown once at creation time (scripts/generate_api_key.sh)
and then discarded.

Scopes control what the key holder can do:
  - read       : GET endpoints
  - write      : POST /v1/applications
  - admin      : Guideline promotion, calibration status
  - reviewer   : Reviewer feedback submission
  - demo_admin : Demo guideline editor
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
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class APIKeyScope(str, enum.Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    REVIEWER = "reviewer"
    DEMO_ADMIN = "demo_admin"


class APIKey(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    A hashed API key for authenticating ComplianceLoop API requests.
    """

    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_keys_key_prefix", "key_prefix"),
        {"comment": "Hashed API keys for API authentication"},
    )

    # ── Key data ──────────────────────────────────────────────────────────────
    key_prefix: Mapped[str] = mapped_column(
        String(8),
        nullable=False,
        index=True,
        comment=(
            "First 8 chars of the plaintext key — shown in UI for identification. "
            "E.g. 'clp_abc1'. Not sensitive but allows key lookup without full hash."
        ),
    )

    key_hash: Mapped[str] = mapped_column(
        String(60),
        nullable=False,
        comment="bcrypt hash of the full plaintext key. Plaintext is never stored.",
    )

    # ── Metadata ──────────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable name for this key. E.g. 'Production NBFC Integration'",
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional description of the key's purpose",
    )

    scopes: Mapped[list[str]] = mapped_column(
        ARRAY(String(50)),
        nullable=False,
        default=list,
        comment="List of scope strings this key is authorised for",
    )

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
        comment="False = key is revoked and will be rejected",
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Optional expiry timestamp — NULL means no expiry",
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp of most recent successful authentication",
    )

    use_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
        comment="Total number of successful authentications",
    )

    created_by: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="Who created this key (admin username or 'system')",
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when key was revoked",
    )

    revoked_by: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="Who revoked this key",
    )

    def __repr__(self) -> str:
        return (
            f"<APIKey id={self.id} "
            f"prefix={self.key_prefix!r} "
            f"name={self.name!r} "
            f"active={self.is_active}>"
        )