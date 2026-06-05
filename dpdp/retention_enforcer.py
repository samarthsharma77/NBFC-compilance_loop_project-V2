"""
ComplianceLoop — DPDP Retention Enforcer
==========================================
Enforces the storage limitation obligation under DPDP Act 2023.

DPDP obligation:
  Personal data must not be retained beyond the period necessary for
  the purpose for which it was collected. Once the purpose is fulfilled
  (i.e. the loan decision is final), the raw PII must be deleted within
  the defined retention window.

Retention model in ComplianceLoop:
  - data_retention_expires_at is set at application ingestion time
  - Default: 90 days after the final decision date (configurable)
  - NBFCs with longer regulatory retention needs (typically 5–8 years for
    audit records) configure this via DPDP_DEFAULT_RETENTION_DAYS env var
  - After expiry: payload_encrypted → NULL, PII columns → NULL
  - Audit hash/HMAC in audit_records is NEVER deleted (non-repudiation)
  - The RetentionEvent table records every wipe for compliance audit

What is wiped vs retained:
  WIPED (PII):
    - payload_encrypted (AES-encrypted full payload blob)
    - collateral_value (financial PII)
    - city_tier (location data)

  RETAINED (non-PII, required for audit non-repudiation):
    - id, applicant_id, pan_hmac (no plaintext PAN)
    - loan_amount_requested, loan_tenure_months, loan_purpose
    - All decision records (outcome, confidence, rationale)
    - All audit_records (hash, HMAC — proves decision was made correctly)
    - retention_wiped = True, retention_wiped_at (audit of the wipe itself)

This balance allows a regulator to verify the integrity of any past decision
(via the audit hash/HMAC) while ensuring the NBFC does not hold raw PII
longer than necessary.

Celery task:
  Triggered by Beat daily at 03:00 UTC.
  Also callable manually: make run-retention-wipe
  Task name: dpdp.retention_enforcer.run_retention_wipe
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Fields to null out on retention wipe
# These are PII or PII-derived fields that must not be retained post-expiry
_PII_FIELDS_TO_WIPE = [
    "payload_encrypted",
    "collateral_value",
    "city_tier",
]

# Batch size for retention wipe queries — process in chunks to avoid lock contention
_WIPE_BATCH_SIZE = 500


# ── Celery task ───────────────────────────────────────────────────────────────

def run_retention_wipe(**kwargs: Any) -> dict[str, Any]:
    """
    Celery task: find and wipe all expired application PII records.

    This function is registered as a Celery task in workers/celery_app.py
    under the name 'dpdp.retention_enforcer.run_retention_wipe'.

    Registered separately to avoid circular imports at worker startup.
    The actual task registration happens in workers/celery_app.py imports list.

    Returns:
        Dict with wipe statistics: {wiped_count, error_count, duration_seconds}
    """
    return asyncio.run(_run_retention_wipe_async())


async def _run_retention_wipe_async() -> dict[str, Any]:
    """
    Async implementation of the retention enforcement wipe.

    Processes applications in batches of _WIPE_BATCH_SIZE to avoid
    holding large transactions open and to allow other DB operations
    to proceed between batches.
    """
    start_time = datetime.now(timezone.utc)
    total_wiped = 0
    total_errors = 0
    task_run_id = f"retention-{start_time.strftime('%Y%m%dT%H%M%S')}"

    logger.info(
        "retention.wipe.started",
        task_run_id=task_run_id,
        started_at=start_time.isoformat(),
    )

    try:
        # Process in batches until no more expired records
        while True:
            batch_count, batch_errors = await _wipe_batch(
                task_run_id=task_run_id,
                batch_size=_WIPE_BATCH_SIZE,
            )
            total_wiped += batch_count
            total_errors += batch_errors

            if batch_count == 0:
                # No more records to wipe
                break

    except Exception as exc:
        logger.error(
            "retention.wipe.failed",
            task_run_id=task_run_id,
            error=str(exc),
            wiped_so_far=total_wiped,
        )
        raise

    duration_seconds = int(
        (datetime.now(timezone.utc) - start_time).total_seconds()
    )

    logger.info(
        "retention.wipe.completed",
        task_run_id=task_run_id,
        total_wiped=total_wiped,
        total_errors=total_errors,
        duration_seconds=duration_seconds,
    )

    # Record Prometheus metrics
    try:
        from observability.metrics import DPDP_RETENTION_WIPES_TOTAL  # noqa: PLC0415
        DPDP_RETENTION_WIPES_TOTAL.labels(
            status="success",
            is_demo="false",
        ).inc(total_wiped)
        if total_errors > 0:
            DPDP_RETENTION_WIPES_TOTAL.labels(
                status="error",
                is_demo="false",
            ).inc(total_errors)
    except Exception:
        pass

    return {
        "wiped_count": total_wiped,
        "error_count": total_errors,
        "duration_seconds": duration_seconds,
        "task_run_id": task_run_id,
    }


async def _wipe_batch(
    task_run_id: str,
    batch_size: int,
) -> tuple[int, int]:
    """
    Wipe one batch of expired application records.

    Args:
        task_run_id: Celery task run ID for RetentionEvent logging.
        batch_size: Maximum number of records to process in this batch.

    Returns:
        Tuple of (wiped_count, error_count).
    """
    from db.session import get_session_context  # noqa: PLC0415
    from models.application import Application  # noqa: PLC0415
    from models.retention_event import RetentionEvent  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415
    from sqlalchemy.dialects.postgresql import UUID as PG_UUID  # noqa: PLC0415
    import os  # noqa: PLC0415

    now = datetime.now(timezone.utc)
    retention_policy_days = int(os.environ.get("DPDP_DEFAULT_RETENTION_DAYS", "90"))
    wiped = 0
    errors = 0

    async with get_session_context() as db:
        # Find expired, not-yet-wiped applications
        stmt = (
            select(Application)
            .where(
                Application.data_retention_expires_at < now,
                Application.retention_wiped.is_(False),
                Application.is_demo.is_(False),  # Never wipe demo data via this task
            )
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )

        result = await db.execute(stmt)
        applications = result.scalars().all()

        if not applications:
            return 0, 0

        for app in applications:
            try:
                # Record fields that will be wiped (for the RetentionEvent log)
                fields_wiped = []

                # Wipe payload_encrypted
                if app.payload_encrypted is not None:
                    app.payload_encrypted = None
                    fields_wiped.append("payload_encrypted")

                # Wipe optional PII fields
                if app.collateral_value is not None:
                    app.collateral_value = None
                    fields_wiped.append("collateral_value")

                if app.city_tier is not None:
                    app.city_tier = None
                    fields_wiped.append("city_tier")

                # Mark as wiped
                app.retention_wiped = True
                app.retention_wiped_at = now

                # Create RetentionEvent audit record
                retention_event = RetentionEvent(
                    application_id=app.id,
                    wiped_at=now,
                    wipe_task_run_id=task_run_id,
                    fields_wiped=",".join(fields_wiped) if fields_wiped else "none",
                    retention_policy_days=retention_policy_days,
                    data_retention_expires_at_snapshot=app.data_retention_expires_at,
                )
                db.add(retention_event)

                wiped += 1

                logger.info(
                    "retention.wipe.application",
                    application_id=str(app.id),
                    fields_wiped=fields_wiped,
                    expired_at=app.data_retention_expires_at.isoformat(),
                )

            except Exception as exc:
                errors += 1
                logger.error(
                    "retention.wipe.application.error",
                    application_id=str(app.id),
                    error=str(exc),
                )
                # Continue with next application — don't fail entire batch
                continue

        await db.commit()

    return wiped, errors


# ── MinIO object deletion ─────────────────────────────────────────────────────

async def wipe_minio_payloads(application_ids: list[str]) -> dict[str, Any]:
    """
    Delete MinIO encrypted payload objects for wiped applications.

    This is called separately from the DB wipe because MinIO deletion
    is eventually consistent — if it fails, we retry without affecting
    the DB wipe. The DB wipe (payload_encrypted=NULL) is the primary
    enforcement; MinIO deletion is belt-and-suspenders.

    Args:
        application_ids: List of UUID strings for wiped applications.

    Returns:
        Dict with {deleted_count, error_count}.
    """
    import os  # noqa: PLC0415
    from db.session import get_session_context  # noqa: PLC0415
    from models.audit_record import AuditRecord  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    deleted = 0
    errors = 0

    try:
        from minio import Minio  # noqa: PLC0415
        from minio.error import S3Error  # noqa: PLC0415

        client = Minio(
            endpoint=os.environ.get("MINIO_ENDPOINT", "localhost:9000"),
            access_key=os.environ.get("MINIO_ACCESS_KEY", ""),
            secret_key=os.environ.get("MINIO_SECRET_KEY", ""),
            secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
        )
        bucket = os.environ.get("MINIO_BUCKET_AUDIT", "complianceloop-audit")

        # Get S3 keys for these applications from audit_records
        async with get_session_context() as db:
            import uuid  # noqa: PLC0415
            app_uuids = [uuid.UUID(aid) for aid in application_ids]
            stmt = (
                select(AuditRecord.payload_s3_key)
                .where(
                    AuditRecord.application_id.in_(app_uuids),
                    AuditRecord.payload_s3_key.isnot(None),
                    AuditRecord.payload_s3_uploaded.is_(True),
                )
            )
            result = await db.execute(stmt)
            s3_keys = [row[0] for row in result.fetchall()]

        for s3_key in s3_keys:
            try:
                client.remove_object(bucket, s3_key)
                deleted += 1
                logger.debug(
                    "retention.minio.deleted",
                    s3_key=s3_key,
                )
            except S3Error as exc:
                errors += 1
                logger.warning(
                    "retention.minio.delete_failed",
                    s3_key=s3_key,
                    error=str(exc),
                )

    except ImportError:
        logger.warning("retention.minio.client_unavailable")
    except Exception as exc:
        logger.error("retention.minio.wipe_failed", error=str(exc))
        errors += 1

    return {"deleted_count": deleted, "error_count": errors}


# ── Compute retention expiry ──────────────────────────────────────────────────

def compute_retention_expiry(
    decision_date: datetime,
    retention_days: int | None = None,
) -> datetime:
    """
    Compute the data_retention_expires_at timestamp for a new application.

    Called at ingestion time to set when PII will be wiped.

    Args:
        decision_date: UTC datetime of the final decision.
                       For new applications, use submission datetime
                       as a conservative estimate (actual decision may be sooner).
        retention_days: Override retention period in days.
                        If None, reads from DPDP_DEFAULT_RETENTION_DAYS env var.

    Returns:
        UTC datetime when PII should be wiped.
    """
    import os  # noqa: PLC0415

    days = retention_days or int(os.environ.get("DPDP_DEFAULT_RETENTION_DAYS", "90"))
    from datetime import timedelta  # noqa: PLC0415
    return decision_date + timedelta(days=days)