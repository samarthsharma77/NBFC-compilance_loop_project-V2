"""
ComplianceLoop — Data Subject Rights Handler
=============================================
Handles DPDP Act 2023 data principal (applicant) rights:

  1. Right to Access (Section 11): Applicant can request what data is held
  2. Right to Correction (Section 12): Applicant can request correction
  3. Right to Erasure (Section 12): Applicant can request deletion of data
  4. Right to Grievance Redressal (Section 13): Applicant can raise complaints
  5. Right to Withdraw Consent (Section 6(4)): Applicant can withdraw consent

Implementation approach:
  - Access requests: Return a summary of non-sensitive data held
    (not the encrypted payload — that requires manual compliance review)
  - Erasure requests: Trigger immediate retention wipe if legally permissible
    (some data must be retained for audit/regulatory purposes — these are excluded)
  - Consent withdrawal: Marks consent as withdrawn; future applications
    from the same applicant will be rejected until fresh consent is obtained

DPDP note on erasure:
  Not all data can be erased on request. The DPDP Act recognises legitimate
  purposes for retention. In the lending context:
    - Audit records (hash/HMAC) CANNOT be erased — regulatory requirement
    - Decision records CANNOT be erased — audit trail requirement
    - Raw PII (payload_encrypted) CAN be erased early on valid request
  The erasure function performs an early retention wipe on the PII fields
  while preserving audit non-repudiation records.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class DataAccessResponse:
    """Response to a data access request (Right to Access)."""
    applicant_id: str
    request_id: str
    generated_at: datetime
    applications_found: int
    data_held: list[dict[str, Any]]
    data_categories: list[str]
    retention_info: dict[str, Any]
    note: str = (
        "This response contains non-sensitive identifiers and decision summaries. "
        "Encrypted personal data requires a formal written request processed by "
        "the compliance team. Contact your NBFC relationship manager."
    )


@dataclass
class ErasureResponse:
    """Response to an erasure request (Right to Erasure)."""
    applicant_id: str
    request_id: str
    processed_at: datetime
    applications_wiped: int
    applications_retained: list[str]
    retained_reason: str
    erasure_complete: bool


# ── Right to Access ───────────────────────────────────────────────────────────

async def handle_access_request(
    applicant_id: str,
    requesting_pan_hmac: str,
) -> DataAccessResponse:
    """
    Handle a DPDP Right to Access request.

    Returns a structured summary of non-sensitive data held for this applicant.
    Does NOT return encrypted payload bytes — those require manual processing.

    Args:
        applicant_id: The applicant's external identifier UUID string.
        requesting_pan_hmac: HMAC of the applicant's PAN for identity verification.
                             Must match the pan_hmac stored for this applicant_id.

    Returns:
        DataAccessResponse with summary of data held.

    Raises:
        ValueError: If applicant_id not found or PAN HMAC does not match.
    """
    import uuid  # noqa: PLC0415
    from db.session import get_session_context  # noqa: PLC0415
    from models.application import Application  # noqa: PLC0415
    from models.decision import Decision  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    request_id = str(uuid.uuid4())

    async with get_session_context() as db:
        # Find all applications for this applicant
        stmt = (
            select(Application)
            .where(
                Application.applicant_id == uuid.UUID(applicant_id),
                Application.pan_hmac == requesting_pan_hmac,
                Application.is_demo.is_(False),
            )
            .order_by(Application.submitted_at.desc())
        )
        result = await db.execute(stmt)
        applications = result.scalars().all()

        if not applications:
            raise ValueError(
                f"No applications found for applicant_id '{applicant_id}' "
                "with the provided PAN. Identity could not be verified."
            )

        data_held = []
        for app in applications:
            # Build non-sensitive data summary
            # NEVER include: payload_encrypted, pan_hmac full value, raw PII
            app_summary: dict[str, Any] = {
                "application_id": str(app.id),
                "submitted_at": app.submitted_at.isoformat(),
                "loan_purpose": app.loan_purpose,
                "loan_amount_requested": float(app.loan_amount_requested),
                "loan_tenure_months": app.loan_tenure_months,
                "dpdp_consent_version": app.dpdp_consent_version,
                "dpdp_consent_at": app.dpdp_consent_at.isoformat(),
                "data_retention_expires_at": app.data_retention_expires_at.isoformat(),
                "retention_wiped": app.retention_wiped,
                "pan_identifier": "****" + app.pan_hmac[-4:],  # Last 4 of HMAC only
            }

            # Get decisions for this application
            decision_stmt = (
                select(Decision)
                .where(Decision.application_id == app.id)
                .order_by(Decision.run_number.asc())
            )
            decision_result = await db.execute(decision_stmt)
            decisions = decision_result.scalars().all()

            app_summary["decisions"] = [
                {
                    "run_number": d.run_number,
                    "outcome": d.outcome.value,
                    "confidence": float(d.confidence),
                    "decided_at": d.created_at.isoformat(),
                    "is_retro_eval": d.is_retro_eval,
                    "guideline_version_id": str(d.guideline_version_id),
                }
                for d in decisions
            ]

            data_held.append(app_summary)

    response = DataAccessResponse(
        applicant_id=applicant_id,
        request_id=request_id,
        generated_at=datetime.now(timezone.utc),
        applications_found=len(applications),
        data_held=data_held,
        data_categories=[
            "Loan application identifiers and metadata",
            "Loan purpose and amount",
            "Compliance decision outcomes",
            "Consent records",
            "Data retention schedule",
        ],
        retention_info={
            "policy": "Personal data retained for configured retention period after final decision",
            "audit_records_retention": "Audit hashes and HMACs retained indefinitely for non-repudiation",
            "contact": "Raise a formal access request with your NBFC for encrypted payload review",
        },
    )

    logger.info(
        "data_subject.access_request.completed",
        applicant_id=applicant_id,
        request_id=request_id,
        applications_found=len(applications),
    )

    return response


# ── Right to Erasure ──────────────────────────────────────────────────────────

async def handle_erasure_request(
    applicant_id: str,
    requesting_pan_hmac: str,
    reason: str = "Data principal erasure request",
) -> ErasureResponse:
    """
    Handle a DPDP Right to Erasure request.

    Triggers an early retention wipe for PII fields on all applications
    for this applicant. Audit records (hash/HMAC) are NOT erased —
    these are required for regulatory non-repudiation.

    Args:
        applicant_id: The applicant's external identifier UUID string.
        requesting_pan_hmac: HMAC of the applicant's PAN for identity verification.
        reason: Reason for erasure (logged for audit).

    Returns:
        ErasureResponse describing what was wiped and what was retained.

    Raises:
        ValueError: If applicant_id not found or PAN HMAC does not match.
    """
    import uuid  # noqa: PLC0415
    from db.session import get_session_context  # noqa: PLC0415
    from models.application import Application  # noqa: PLC0415
    from models.retention_event import RetentionEvent  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    request_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    wiped_ids = []
    retained_ids = []

    async with get_session_context() as db:
        stmt = (
            select(Application)
            .where(
                Application.applicant_id == uuid.UUID(applicant_id),
                Application.pan_hmac == requesting_pan_hmac,
                Application.is_demo.is_(False),
            )
        )
        result = await db.execute(stmt)
        applications = result.scalars().all()

        if not applications:
            raise ValueError(
                f"No applications found for applicant_id '{applicant_id}'. "
                "Identity could not be verified."
            )

        for app in applications:
            if app.retention_wiped:
                # Already wiped — nothing to do
                retained_ids.append(str(app.id))
                continue

            # Wipe PII fields immediately (early erasure)
            fields_wiped = []

            if app.payload_encrypted is not None:
                app.payload_encrypted = None
                fields_wiped.append("payload_encrypted")

            if app.collateral_value is not None:
                app.collateral_value = None
                fields_wiped.append("collateral_value")

            if app.city_tier is not None:
                app.city_tier = None
                fields_wiped.append("city_tier")

            app.retention_wiped = True
            app.retention_wiped_at = now

            # Record retention event
            retention_event = RetentionEvent(
                application_id=app.id,
                wiped_at=now,
                wipe_task_run_id=f"erasure-request-{request_id}",
                fields_wiped=",".join(fields_wiped) if fields_wiped else "none",
                retention_policy_days=0,  # Immediate erasure on request
                data_retention_expires_at_snapshot=app.data_retention_expires_at,
            )
            db.add(retention_event)
            wiped_ids.append(str(app.id))

        await db.commit()

    logger.info(
        "data_subject.erasure_request.completed",
        applicant_id=applicant_id,
        request_id=request_id,
        wiped_count=len(wiped_ids),
        retained_count=len(retained_ids),
        reason=reason,
    )

    return ErasureResponse(
        applicant_id=applicant_id,
        request_id=request_id,
        processed_at=now,
        applications_wiped=len(wiped_ids),
        applications_retained=retained_ids,
        retained_reason=(
            "Audit records (decision hash and HMAC) are retained indefinitely "
            "for regulatory non-repudiation purposes under RBI NBFC directions. "
            "Decision outcomes are retained for dispute resolution. "
            "No personal identification data remains in retained records."
        ),
        erasure_complete=len(retained_ids) == 0,
    )


# ── Right to Withdraw Consent ─────────────────────────────────────────────────

async def handle_consent_withdrawal(
    applicant_id: str,
    requesting_pan_hmac: str,
) -> dict[str, Any]:
    """
    Handle a DPDP consent withdrawal request.

    Marks all active applications for this applicant as having withdrawn consent.
    Future applications from this applicant will require fresh consent.

    Note: Consent withdrawal does NOT retroactively invalidate decisions
    already made — processing was lawful at the time consent was given.
    It only prevents future processing.

    Args:
        applicant_id: The applicant's external identifier UUID string.
        requesting_pan_hmac: HMAC of the applicant's PAN for identity verification.

    Returns:
        Dict with withdrawal confirmation.
    """
    import uuid  # noqa: PLC0415
    from db.session import get_session_context  # noqa: PLC0415
    from models.application import Application  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    now = datetime.now(timezone.utc)

    async with get_session_context() as db:
        stmt = (
            select(Application)
            .where(
                Application.applicant_id == uuid.UUID(applicant_id),
                Application.pan_hmac == requesting_pan_hmac,
                Application.is_demo.is_(False),
            )
        )
        result = await db.execute(stmt)
        applications = result.scalars().all()

        if not applications:
            raise ValueError(
                f"No applications found for applicant_id '{applicant_id}'."
            )

        # Record consent withdrawal by setting dpdp_consent_given to False
        # on all applications — this is informational (consent was valid at
        # time of submission; this records the withdrawal for audit purposes)
        for app in applications:
            app.dpdp_consent_given = False

        await db.commit()

    logger.info(
        "data_subject.consent_withdrawal.completed",
        applicant_id=applicant_id,
        applications_affected=len(applications),
        withdrawn_at=now.isoformat(),
    )

    return {
        "applicant_id": applicant_id,
        "consent_withdrawn_at": now.isoformat(),
        "applications_affected": len(applications),
        "message": (
            "Consent has been withdrawn. Future applications will require fresh consent. "
            "Prior decisions made under valid consent remain legally effective."
        ),
    }