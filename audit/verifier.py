"""
ComplianceLoop — Audit Verifier
=================================
Verifies the integrity of audit records in response to regulator queries
or internal compliance reviews.

Verification protocol (from docs/runbooks/regulator_audit_response.md):
  1. Retrieve audit_record row from PostgreSQL by decision_id
  2. Download encrypted payload from MinIO at payload_s3_key
  3. Decrypt payload using AES_KEY
  4. Recompute SHA-256 of agent_outputs from decrypted payload
  5. Compare recomputed hash vs audit_records.agent_outputs_hash
  6. Recompute HMAC-SHA256 using SERVER_HMAC_KEY (and PREVIOUS key if rotating)
  7. Compare recomputed HMAC vs audit_records.record_hmac
  8. Both match → record is intact and authentic
     Either fails → record has been tampered with

This module provides:
  - verify_by_decision_id(): verify a single audit record (primary API)
  - verify_by_application_id(): verify all records for an application
  - verify_without_minio(): verify using only Postgres data (hash check only,
    no payload decryption — useful when MinIO is unavailable)
  - VerificationResult: structured result with full details for reporting

Called by:
  - scripts/verify_audit_record.sh (make verify-audit ID=<decision_id>)
  - GET /v1/applications/{id}/audit API endpoint
  - Integration test: tests/integration/test_audit_integrity.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Result data class ─────────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    """
    Result of a single audit record integrity verification.

    All fields are populated regardless of pass/fail so the result
    can be included in a regulator report.
    """
    decision_id: str
    application_id: str
    guideline_version_id: str
    written_at: str                     # ISO 8601 string
    outcome: str                        # From decision record
    is_valid: bool                      # True = record intact and authentic
    hash_check_passed: bool             # SHA-256 content hash verified
    hmac_check_passed: bool             # HMAC authenticity verified
    minio_payload_available: bool       # MinIO payload was accessible
    failure_reason: str = ""            # Empty string on success
    agent_outputs_hash: str = ""        # From audit_records
    record_hmac_prefix: str = ""        # First 16 chars of HMAC (safe to show)
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_report_dict(self) -> dict[str, Any]:
        """Serialise for inclusion in regulator report or API response."""
        return {
            "decision_id": self.decision_id,
            "application_id": self.application_id,
            "guideline_version_id": self.guideline_version_id,
            "written_at": self.written_at,
            "outcome": self.outcome,
            "is_valid": self.is_valid,
            "hash_check_passed": self.hash_check_passed,
            "hmac_check_passed": self.hmac_check_passed,
            "minio_payload_available": self.minio_payload_available,
            "failure_reason": self.failure_reason,
            "agent_outputs_hash_prefix": self.agent_outputs_hash[:16] + "...",
            "record_hmac_prefix": self.record_hmac_prefix,
            "verified_at": self.verified_at,
        }


# ── Primary verification function ─────────────────────────────────────────────

async def verify_by_decision_id(
    decision_id: str,
    is_demo: bool = False,
) -> VerificationResult:
    """
    Verify the integrity of an audit record by its decision_id.

    This is the primary verification entry point. It:
      1. Fetches the audit_record from PostgreSQL
      2. Attempts to download and decrypt the MinIO payload
      3. Runs both hash and HMAC verification
      4. Returns a VerificationResult with full details

    Args:
        decision_id: UUID string of the Decision record.
        is_demo: Whether to query the demo database.

    Returns:
        VerificationResult — check is_valid for pass/fail.

    Raises:
        ValueError: If no audit record exists for this decision_id.
    """
    import uuid  # noqa: PLC0415
    from db.session import get_session_context  # noqa: PLC0415
    from models.audit_record import AuditRecord  # noqa: PLC0415
    from models.decision import Decision  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    # Step 1: Fetch audit record and decision
    async with get_session_context(is_demo=is_demo) as db:
        audit_stmt = select(AuditRecord).where(
            AuditRecord.decision_id == uuid.UUID(decision_id)
        )
        audit_result = await db.execute(audit_stmt)
        audit_record = audit_result.scalar_one_or_none()

        if audit_record is None:
            raise ValueError(
                f"No audit record found for decision_id '{decision_id}'. "
                "This decision may not have a compliance audit trail."
            )

        decision_stmt = select(Decision).where(
            Decision.id == uuid.UUID(decision_id)
        )
        decision_result = await db.execute(decision_stmt)
        decision = decision_result.scalar_one_or_none()

    outcome = decision.outcome.value if decision else "UNKNOWN"

    # Step 2: Attempt MinIO payload download
    minio_available = False
    agent_outputs_from_minio: dict[str, Any] | None = None

    if audit_record.payload_s3_key and audit_record.payload_s3_uploaded:
        try:
            agent_outputs_from_minio = await _download_and_decrypt_payload(
                s3_key=audit_record.payload_s3_key,
                expected_keys=["agent_outputs"],
            )
            minio_available = True
        except Exception as exc:
            logger.warning(
                "verifier.minio_unavailable",
                decision_id=decision_id,
                error=str(exc),
            )

    # Step 3: Run verification
    if minio_available and agent_outputs_from_minio is not None:
        # Full verification: hash + HMAC with MinIO payload
        is_valid, failure_reason = _run_full_verification(
            audit_record=audit_record,
            agent_outputs=agent_outputs_from_minio.get("agent_outputs", {}),
        )
        hash_passed = "hash" not in failure_reason.lower() if not is_valid else True
        hmac_passed = "hmac" not in failure_reason.lower() if not is_valid else True
    else:
        # Partial verification: HMAC only using data from Postgres
        # (cannot verify hash without MinIO payload)
        is_valid, failure_reason, hash_passed, hmac_passed = (
            _run_hmac_only_verification(audit_record=audit_record)
        )

    result = VerificationResult(
        decision_id=decision_id,
        application_id=str(audit_record.application_id),
        guideline_version_id=str(audit_record.guideline_version_id),
        written_at=audit_record.written_at.isoformat(),
        outcome=outcome,
        is_valid=is_valid,
        hash_check_passed=hash_passed,
        hmac_check_passed=hmac_passed,
        minio_payload_available=minio_available,
        failure_reason=failure_reason,
        agent_outputs_hash=audit_record.agent_outputs_hash,
        record_hmac_prefix=audit_record.record_hmac[:16],
    )

    log_method = logger.info if is_valid else logger.error
    log_method(
        "audit.verification.completed",
        decision_id=decision_id,
        is_valid=is_valid,
        hash_passed=hash_passed,
        hmac_passed=hmac_passed,
        minio_available=minio_available,
        failure_reason=failure_reason if not is_valid else "",
    )

    return result


async def verify_by_application_id(
    application_id: str,
    is_demo: bool = False,
) -> list[VerificationResult]:
    """
    Verify all audit records for an application (full decision chain).

    Returns results for all runs (original + all retro-eval runs) ordered
    by run_number ascending.

    Args:
        application_id: UUID string of the Application.
        is_demo: Whether to query the demo database.

    Returns:
        List of VerificationResult, one per pipeline run.
    """
    import uuid  # noqa: PLC0415
    from db.session import get_session_context  # noqa: PLC0415
    from models.audit_record import AuditRecord  # noqa: PLC0415
    from models.decision import Decision  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    async with get_session_context(is_demo=is_demo) as db:
        stmt = (
            select(AuditRecord)
            .where(AuditRecord.application_id == uuid.UUID(application_id))
            .order_by(AuditRecord.written_at.asc())
        )
        result = await db.execute(stmt)
        audit_records = result.scalars().all()

    results = []
    for record in audit_records:
        try:
            verification = await verify_by_decision_id(
                decision_id=str(record.decision_id),
                is_demo=is_demo,
            )
            results.append(verification)
        except Exception as exc:
            logger.error(
                "verifier.record_failed",
                decision_id=str(record.decision_id),
                error=str(exc),
            )

    return results


# ── Verification logic ────────────────────────────────────────────────────────

def _run_full_verification(
    audit_record: Any,
    agent_outputs: dict[str, Any],
) -> tuple[bool, str]:
    """
    Run full hash + HMAC verification using decrypted MinIO payload.

    Returns:
        Tuple of (is_valid, failure_reason).
    """
    from audit.hasher import verify_audit_record_integrity  # noqa: PLC0415

    return verify_audit_record_integrity(
        stored_agent_outputs_hash=audit_record.agent_outputs_hash,
        stored_record_hmac=audit_record.record_hmac,
        agent_outputs=agent_outputs,
        decision_id=str(audit_record.decision_id),
        guideline_version_id=str(audit_record.guideline_version_id),
        written_at=audit_record.written_at,
    )


def _run_hmac_only_verification(
    audit_record: Any,
) -> tuple[bool, str, bool, bool]:
    """
    Run HMAC-only verification when MinIO is unavailable.

    Cannot verify the agent_outputs_hash without the payload, but
    can still verify the HMAC over the stored hash value.

    Returns:
        Tuple of (is_valid, failure_reason, hash_check_passed, hmac_check_passed).
    """
    from security.hmac_utils import verify_record_hmac  # noqa: PLC0415
    from audit.hasher import _serialise_written_at  # noqa: PLC0415

    written_at_str = _serialise_written_at(audit_record.written_at)

    hmac_valid = verify_record_hmac(
        stored_hmac=audit_record.record_hmac,
        agent_outputs_hash=audit_record.agent_outputs_hash,
        decision_id=str(audit_record.decision_id),
        guideline_version_id=str(audit_record.guideline_version_id),
        written_at=written_at_str,
    )

    if hmac_valid:
        return (
            True,
            "",
            False,   # hash_check: not performed (no payload)
            True,    # hmac_check: passed
        )
    else:
        return (
            False,
            "HMAC verification failed (MinIO payload unavailable for hash check). "
            "The stored HMAC does not match the expected value for this audit record.",
            False,
            False,
        )


# ── MinIO payload download ────────────────────────────────────────────────────

async def _download_and_decrypt_payload(
    s3_key: str,
    expected_keys: list[str],
) -> dict[str, Any]:
    """
    Download encrypted payload from MinIO and decrypt it.

    Args:
        s3_key: MinIO object key.
        expected_keys: Keys expected in the decrypted JSON (for validation).

    Returns:
        Decrypted payload as a dict.

    Raises:
        Exception: If download, decryption, or JSON parsing fails.
    """
    import asyncio  # noqa: PLC0415
    import io  # noqa: PLC0415
    import json  # noqa: PLC0415
    import os  # noqa: PLC0415

    from minio import Minio  # noqa: PLC0415
    from security.encryption import decrypt_payload  # noqa: PLC0415

    bucket = os.environ.get("MINIO_BUCKET_AUDIT", "complianceloop-audit")
    client = Minio(
        endpoint=os.environ.get("MINIO_ENDPOINT", "localhost:9000"),
        access_key=os.environ.get("MINIO_ACCESS_KEY", ""),
        secret_key=os.environ.get("MINIO_SECRET_KEY", ""),
        secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
    )

    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None,
        lambda: client.get_object(bucket, s3_key),
    )
    encrypted_bytes = response.read()
    response.close()
    response.release_conn()

    decrypted_bytes = decrypt_payload(encrypted_bytes)
    payload = json.loads(decrypted_bytes.decode("utf-8"))

    for key in expected_keys:
        if key not in payload:
            raise ValueError(
                f"Decrypted payload missing expected key '{key}'. "
                "Payload may be corrupted or from an incompatible version."
            )

    return payload