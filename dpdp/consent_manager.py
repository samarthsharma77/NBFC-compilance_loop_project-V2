"""
ComplianceLoop — DPDP Consent Manager
=======================================
Enforces the notice and consent obligations under the Digital Personal
Data Protection Act 2023 (DPDP Act).

DPDP obligations handled here:
  1. Notice      : Applicant must be informed of what data is collected and why
  2. Consent     : Specific, informed, voluntary consent required before processing
  3. Version     : Consent must reference the CURRENT active consent form version
  4. Freshness   : Consent timestamp must be within 24 hours (anti-replay)
  5. Withdrawal  : Applicants can withdraw consent (handled in data_subject_handler.py)

The consent gate is the FIRST middleware check in the API layer — if it
fails, no application data is written to the database. The request is
rejected with HTTP 422 and code DPDP_CONSENT_INVALID before any PII
touches the pipeline.

Consent validation rules (all must pass):
  1. dpdp_consent == True  (explicit boolean — not truthy, not string)
  2. consent_version matches the current active ConsentVersion.version_id
  3. consent_timestamp is within the last DPDP_CONSENT_VALIDITY_HOURS (default 24)
  4. consent_timestamp is not in the future (clock skew protection)

Why 24-hour validity?
  Prevents replay attacks where a captured consent token is reused to
  submit fraudulent applications. The applicant must have actively consented
  within the last 24 hours for the application to proceed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Consent validation result ─────────────────────────────────────────────────

class ConsentValidationResult:
    """Result of a consent validation check."""

    __slots__ = ("is_valid", "error_code", "error_message", "active_version_id")

    def __init__(
        self,
        is_valid: bool,
        error_code: str | None = None,
        error_message: str | None = None,
        active_version_id: str | None = None,
    ) -> None:
        self.is_valid = is_valid
        self.error_code = error_code
        self.error_message = error_message
        self.active_version_id = active_version_id

    def __bool__(self) -> bool:
        return self.is_valid


# ── Core validation function ──────────────────────────────────────────────────

async def validate_consent(
    dpdp_consent: Any,
    consent_version: str,
    consent_timestamp: datetime,
    validity_hours: int = 24,
) -> ConsentValidationResult:
    """
    Validate DPDP consent for an incoming application request.

    This is called by the DPDPConsentMiddleware on every
    POST /v1/applications request, before any data is written.

    Args:
        dpdp_consent: The consent flag from the request body.
                      Must be exactly True (boolean) — not "true" string.
        consent_version: The consent form version string from the request.
                         Must match the current active ConsentVersion.version_id.
        consent_timestamp: UTC datetime when the applicant gave consent.
                           Must be within the last validity_hours and not in future.
        validity_hours: How many hours the consent remains valid (default 24).

    Returns:
        ConsentValidationResult with is_valid=True on success,
        or is_valid=False with error_code and error_message on failure.
    """
    import os  # noqa: PLC0415

    # Override validity hours from environment if set
    env_validity = int(os.environ.get("DPDP_CONSENT_VALIDITY_HOURS", str(validity_hours)))

    # ── Check 1: Consent flag must be exactly True ────────────────────────────
    if dpdp_consent is not True:
        logger.warning(
            "consent.validation.failed",
            reason="consent_not_given",
            consent_value=repr(dpdp_consent),
        )
        return ConsentValidationResult(
            is_valid=False,
            error_code="DPDP_CONSENT_NOT_GIVEN",
            error_message=(
                "DPDP consent is required. Set dpdp_consent: true in the request body. "
                "The applicant must explicitly consent to data processing before "
                "the application can be submitted."
            ),
        )

    # ── Check 2: Consent timestamp not in the future ──────────────────────────
    now_utc = datetime.now(timezone.utc)

    # Ensure consent_timestamp is timezone-aware
    if consent_timestamp.tzinfo is None:
        consent_timestamp = consent_timestamp.replace(tzinfo=timezone.utc)

    if consent_timestamp > now_utc + timedelta(minutes=5):
        # Allow 5 minutes of clock skew
        logger.warning(
            "consent.validation.failed",
            reason="consent_timestamp_in_future",
            consent_timestamp=consent_timestamp.isoformat(),
            server_time=now_utc.isoformat(),
        )
        return ConsentValidationResult(
            is_valid=False,
            error_code="DPDP_CONSENT_TIMESTAMP_FUTURE",
            error_message=(
                "consent_timestamp is in the future. "
                "Ensure the client clock is synchronised with NTP."
            ),
        )

    # ── Check 3: Consent timestamp within validity window ────────────────────
    consent_cutoff = now_utc - timedelta(hours=env_validity)
    if consent_timestamp < consent_cutoff:
        age_hours = (now_utc - consent_timestamp).total_seconds() / 3600
        logger.warning(
            "consent.validation.failed",
            reason="consent_expired",
            age_hours=round(age_hours, 2),
            validity_hours=env_validity,
        )
        return ConsentValidationResult(
            is_valid=False,
            error_code="DPDP_CONSENT_EXPIRED",
            error_message=(
                f"Consent is {age_hours:.1f} hours old and has expired "
                f"(maximum {env_validity} hours). "
                "The applicant must re-consent before submitting the application."
            ),
        )

    # ── Check 4: Consent version matches active version ───────────────────────
    active_version = await get_active_consent_version()

    if active_version is None:
        logger.error(
            "consent.validation.error",
            reason="no_active_consent_version",
        )
        return ConsentValidationResult(
            is_valid=False,
            error_code="DPDP_NO_ACTIVE_CONSENT_VERSION",
            error_message=(
                "No active consent version is configured. "
                "System configuration error — contact support."
            ),
        )

    if consent_version != active_version.version_id:
        logger.warning(
            "consent.validation.failed",
            reason="stale_consent_version",
            submitted_version=consent_version,
            active_version=active_version.version_id,
        )
        return ConsentValidationResult(
            is_valid=False,
            error_code="DPDP_CONSENT_VERSION_MISMATCH",
            error_message=(
                f"Consent version '{consent_version}' is not the current version. "
                f"Current version is '{active_version.version_id}'. "
                "Re-present the updated consent notice to the applicant and obtain fresh consent."
            ),
            active_version_id=active_version.version_id,
        )

    logger.info(
        "consent.validation.passed",
        consent_version=consent_version,
        consent_age_seconds=int((now_utc - consent_timestamp).total_seconds()),
    )

    return ConsentValidationResult(
        is_valid=True,
        active_version_id=active_version.version_id,
    )


# ── Consent version management ────────────────────────────────────────────────

async def get_active_consent_version() -> Any | None:
    """
    Retrieve the currently active ConsentVersion from the database.

    Results are cached in Redis for 5 minutes to avoid a DB query on
    every API request. Cache is invalidated when a new consent version
    is activated.

    Returns:
        ConsentVersion ORM object if one is active, None otherwise.
    """
    from db.session import get_session_context  # noqa: PLC0415
    from models.consent_version import ConsentVersion  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    async with get_session_context() as db:
        stmt = (
            select(ConsentVersion)
            .where(ConsentVersion.is_active.is_(True))
            .limit(1)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()


async def activate_consent_version(
    new_version_id: str,
    activated_by: str,
) -> None:
    """
    Activate a new consent version, deactivating the previous one.

    This is an admin operation — called when the NBFC updates its
    DPDP consent notice language (e.g. to reflect new DPDP Rules).

    After calling this, all subsequent POST /v1/applications must
    reference the new version_id in their consent_version field.
    Applications with the old version_id will be rejected.

    Args:
        new_version_id: The version_id string of the version to activate.
        activated_by: Identifier of the admin performing the activation.

    Raises:
        ValueError: If new_version_id does not exist in the database.
    """
    from datetime import datetime, timezone  # noqa: PLC0415
    from db.session import get_session_context  # noqa: PLC0415
    from models.consent_version import ConsentVersion  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    async with get_session_context() as db:
        # Find the new version
        stmt = select(ConsentVersion).where(
            ConsentVersion.version_id == new_version_id
        )
        result = await db.execute(stmt)
        new_version = result.scalar_one_or_none()

        if new_version is None:
            raise ValueError(
                f"Consent version '{new_version_id}' does not exist in the database."
            )

        # Deactivate current active version
        stmt_active = select(ConsentVersion).where(
            ConsentVersion.is_active.is_(True)
        )
        result_active = await db.execute(stmt_active)
        current_active = result_active.scalar_one_or_none()

        if current_active is not None:
            current_active.is_active = False
            current_active.superseded_at = datetime.now(timezone.utc)

        # Activate new version
        new_version.is_active = True
        new_version.effective_from = datetime.now(timezone.utc)

        await db.commit()

    logger.info(
        "consent.version.activated",
        new_version_id=new_version_id,
        previous_version_id=current_active.version_id if current_active else None,
        activated_by=activated_by,
    )


async def get_consent_version_text(version_id: str) -> str | None:
    """
    Retrieve the full consent text for a given version.

    Used by the API to serve the current consent notice to client
    applications so they can present it to applicants before submission.

    Args:
        version_id: The version_id string to look up.

    Returns:
        Full consent text string, or None if version not found.
    """
    from db.session import get_session_context  # noqa: PLC0415
    from models.consent_version import ConsentVersion  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    async with get_session_context() as db:
        stmt = select(ConsentVersion).where(
            ConsentVersion.version_id == version_id
        )
        result = await db.execute(stmt)
        version = result.scalar_one_or_none()
        return version.consent_text if version else None