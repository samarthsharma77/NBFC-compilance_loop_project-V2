"""
ComplianceLoop — Audit S3 Uploader
=====================================
Handles uploading encrypted audit payloads to MinIO (S3-compatible).

Architecture:
  The audit write has two parts:
  1. Synchronous: Write audit_record row to PostgreSQL (blocking, pre-response)
  2. Asynchronous: Upload encrypted payload to MinIO (non-blocking, post-write)

  PostgreSQL is the source of truth. MinIO stores the full encrypted payload
  for long-term archival and regulator access. If MinIO upload fails, the
  Postgres record still exists with payload_s3_uploaded=False.

  A Celery Beat task (every 30 minutes) calls retry_pending_uploads() to
  re-attempt any failed uploads. This gives at-least-once delivery to MinIO.

Payload format stored in MinIO:
  The object stored at audit/{year}/{month}/{decision_id}.json.enc is:
  AES-256-GCM encrypted JSON containing:
  {
    "application_id": "...",
    "decision_id": "...",
    "guideline_version_id": "...",
    "written_at": "...",
    "agent_outputs": { document: {...}, sanctions: {...}, ... },
    "outcome": "APPROVE|REVIEW|REJECT",
    "confidence": 0.95,
    "rationale_chain": [...],
  }

  The encryption key is AES_KEY from environment/Vault.
  The object is NOT publicly accessible (MinIO bucket policy is private).

Celery task name: audit.s3_uploader.retry_pending_uploads
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Upload function ───────────────────────────────────────────────────────────

async def upload_audit_payload(
    decision_id: str,
    application_id: str,
    guideline_version_id: str,
    written_at: datetime,
    agent_outputs: dict[str, Any],
    outcome: str,
    confidence: float,
    rationale_chain: list[dict[str, Any]],
    s3_key: str,
) -> bool:
    """
    Encrypt and upload the full audit payload to MinIO.

    This runs asynchronously after the Postgres audit_record write.
    On success, sets audit_records.payload_s3_uploaded = True.
    On failure, logs the error — retry_pending_uploads() will re-attempt.

    Args:
        decision_id: UUID string of the Decision.
        application_id: UUID string of the Application.
        guideline_version_id: UUID string of the GuidelineVersion.
        written_at: UTC datetime of the audit write.
        agent_outputs: Dict of all five AgentResult objects.
        outcome: APPROVE, REVIEW, or REJECT.
        confidence: Decision confidence score.
        rationale_chain: Ordered list of RationaleEntry objects.
        s3_key: MinIO object key (from audit/hasher.compute_payload_s3_key).

    Returns:
        True if upload succeeded, False otherwise.
    """
    try:
        # Build payload
        payload = {
            "application_id": application_id,
            "decision_id": decision_id,
            "guideline_version_id": guideline_version_id,
            "written_at": written_at.isoformat(),
            "agent_outputs": agent_outputs,
            "outcome": outcome,
            "confidence": confidence,
            "rationale_chain": rationale_chain,
        }

        # Serialise to JSON bytes
        payload_bytes = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=_json_default,
        ).encode("utf-8")

        # Encrypt with AES-256-GCM
        from security.encryption import encrypt_payload  # noqa: PLC0415
        encrypted_bytes = encrypt_payload(payload_bytes)

        # Upload to MinIO
        await _upload_to_minio(encrypted_bytes, s3_key)

        # Update payload_s3_uploaded flag in database
        await _mark_uploaded(decision_id=decision_id, s3_key=s3_key)

        logger.info(
            "audit.s3.uploaded",
            decision_id=decision_id,
            s3_key=s3_key,
            payload_size_bytes=len(encrypted_bytes),
        )

        from observability.metrics import AUDIT_MINIO_UPLOAD_TOTAL  # noqa: PLC0415
        AUDIT_MINIO_UPLOAD_TOTAL.labels(status="success", is_demo="false").inc()

        return True

    except Exception as exc:
        logger.error(
            "audit.s3.upload_failed",
            decision_id=decision_id,
            s3_key=s3_key,
            error=str(exc),
        )
        from observability.metrics import AUDIT_MINIO_UPLOAD_TOTAL  # noqa: PLC0415
        AUDIT_MINIO_UPLOAD_TOTAL.labels(status="error", is_demo="false").inc()
        return False


async def _upload_to_minio(encrypted_bytes: bytes, s3_key: str) -> None:
    """Upload encrypted bytes to MinIO at the given object key."""
    import asyncio  # noqa: PLC0415

    bucket = os.environ.get("MINIO_BUCKET_AUDIT", "complianceloop-audit")
    endpoint = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
    access_key = os.environ.get("MINIO_ACCESS_KEY", "")
    secret_key = os.environ.get("MINIO_SECRET_KEY", "")
    secure = os.environ.get("MINIO_SECURE", "false").lower() == "true"

    try:
        from minio import Minio  # noqa: PLC0415
        from minio.error import S3Error  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "minio package is required for audit uploads. "
            "Install with: pip install -r requirements/worker.txt"
        ) from exc

    client = Minio(
        endpoint=endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
    )

    # Run blocking MinIO call in thread pool (it's a sync client)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None,
        lambda: client.put_object(
            bucket_name=bucket,
            object_name=s3_key,
            data=io.BytesIO(encrypted_bytes),
            length=len(encrypted_bytes),
            content_type="application/octet-stream",
            metadata={
                "x-compliance-encrypted": "aes-256-gcm",
                "x-compliance-version": "1",
            },
        )
    )


async def _mark_uploaded(decision_id: str, s3_key: str) -> None:
    """
    Update audit_records.payload_s3_uploaded = True after successful upload.
    Also ensures payload_s3_key is set correctly.
    """
    import uuid  # noqa: PLC0415
    from db.session import get_session_context  # noqa: PLC0415
    from models.audit_record import AuditRecord  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    async with get_session_context() as db:
        stmt = select(AuditRecord).where(
            AuditRecord.decision_id == uuid.UUID(decision_id)
        ).with_for_update()
        result = await db.execute(stmt)
        record = result.scalar_one_or_none()

        if record is not None:
            record.payload_s3_uploaded = True
            record.payload_s3_key = s3_key
            await db.commit()


# ── Retry task for pending uploads ────────────────────────────────────────────

def retry_pending_uploads() -> dict[str, Any]:
    """
    Celery task: retry all audit records with payload_s3_uploaded=False.

    Called by Beat every 30 minutes. Finds all audit records where
    MinIO upload is pending or failed and retries the upload.

    This is the at-least-once delivery guarantee for MinIO.
    PostgreSQL is always written first (blocking) — this task ensures
    the MinIO copy eventually exists.

    Returns:
        Dict with {attempted, succeeded, failed}.
    """
    return asyncio.run(_retry_pending_uploads_async())


async def _retry_pending_uploads_async() -> dict[str, Any]:
    """Async implementation of pending upload retry."""
    import uuid  # noqa: PLC0415
    from db.session import get_session_context  # noqa: PLC0415
    from models.audit_record import AuditRecord  # noqa: PLC0415
    from models.decision import Decision  # noqa: PLC0415
    from models.application import Application  # noqa: PLC0415
    from sqlalchemy import select, and_  # noqa: PLC0415
    from security.encryption import decrypt_payload  # noqa: PLC0415

    attempted = 0
    succeeded = 0
    failed = 0

    async with get_session_context() as db:
        # Find audit records where MinIO upload has not completed
        stmt = (
            select(AuditRecord)
            .where(
                and_(
                    AuditRecord.payload_s3_uploaded.is_(False),
                    AuditRecord.is_demo.is_(False),
                )
            )
            .limit(100)  # Process in batches of 100
        )
        result = await db.execute(stmt)
        pending_records = result.scalars().all()

    if not pending_records:
        return {"attempted": 0, "succeeded": 0, "failed": 0}

    logger.info(
        "audit.s3.retry.started",
        pending_count=len(pending_records),
    )

    for record in pending_records:
        attempted += 1
        try:
            # Get the decision for this audit record
            async with get_session_context() as db:
                decision_stmt = select(Decision).where(
                    Decision.id == record.decision_id
                )
                decision_result = await db.execute(decision_stmt)
                decision = decision_result.scalar_one_or_none()

                if decision is None:
                    logger.warning(
                        "audit.s3.retry.decision_not_found",
                        decision_id=str(record.decision_id),
                    )
                    failed += 1
                    continue

                # Get encrypted payload from application
                app_stmt = select(Application).where(
                    Application.id == record.application_id
                )
                app_result = await db.execute(app_stmt)
                application = app_result.scalar_one_or_none()

            if application is None or application.payload_encrypted is None:
                logger.warning(
                    "audit.s3.retry.payload_unavailable",
                    application_id=str(record.application_id),
                )
                failed += 1
                continue

            # Compute S3 key
            from audit.hasher import compute_payload_s3_key  # noqa: PLC0415
            s3_key = compute_payload_s3_key(
                decision_id=str(record.decision_id),
                written_at=record.written_at,
            )

            # Retry upload
            success = await upload_audit_payload(
                decision_id=str(record.decision_id),
                application_id=str(record.application_id),
                guideline_version_id=str(record.guideline_version_id),
                written_at=record.written_at,
                agent_outputs=decision.agent_outputs,
                outcome=decision.outcome.value,
                confidence=float(decision.confidence),
                rationale_chain=decision.rationale_chain,
                s3_key=s3_key,
            )

            if success:
                succeeded += 1
            else:
                failed += 1

        except Exception as exc:
            failed += 1
            logger.error(
                "audit.s3.retry.error",
                decision_id=str(record.decision_id),
                error=str(exc),
            )

    logger.info(
        "audit.s3.retry.completed",
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
    )

    return {"attempted": attempted, "succeeded": succeeded, "failed": failed}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _json_default(obj: Any) -> Any:
    """JSON serialisation fallback for datetime and UUID types."""
    from datetime import datetime  # noqa: PLC0415
    import uuid  # noqa: PLC0415
    import enum  # noqa: PLC0415
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, enum.Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serialisable")