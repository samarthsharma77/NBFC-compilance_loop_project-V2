"""
ComplianceLoop — DPDP Breach Response
=======================================
Implements the breach response obligations under DPDP Act 2023.

DPDP breach obligations:
  1. Notification to Data Protection Board within 72 hours of becoming
     aware of a personal data breach
  2. Notification to affected Data Principals (applicants)
  3. Documentation of the breach, its scope, and remediation steps

This module provides:
  - breach_response(): Python-callable breach response (used by API and scripts)
  - The break_glass() PostgreSQL stored procedure (migration 0005) handles
    the DB-level flagging and is the primary breach trigger.

Breach response steps (automated):
  1. Flag audit_records.breach_flag = True for affected records
  2. Record breach_flagged_at timestamp
  3. Freeze pending retro-eval jobs that touch affected records
     (to prevent further processing of potentially compromised data)
  4. Queue BREACH_ALERT notifications to affected applicants via notification_outbox
  5. Generate a breach report summarising scope, categories, and timeline
  6. Queue notification to DPDP Board contact email

Manual steps (not automated — see docs/runbooks/breach_response.md):
  - Assess and contain the breach
  - Submit formal notification to Data Protection Board
  - Coordinate with legal and compliance teams
  - Post-breach audit review

Breach severity levels:
  - LOW    : Limited scope, no sensitive financial data exposed
  - MEDIUM : PII exposed but no financial fraud risk
  - HIGH   : Financial data or identity documents potentially exposed
  - CRITICAL: Active fraud risk, regulatory notification mandatory immediately

The break_glass() PostgreSQL procedure (from migration 0005) is the
fastest path — directly callable from psql or via make break-glass.
This Python module provides the application-layer wrapper with
additional logic (freezing retro-eval, generating reports).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class BreachScope:
    """Describes the scope of a data breach."""
    application_ids: list[str] = field(default_factory=list)
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    estimated_records_affected: int = 0
    data_categories_affected: list[str] = field(default_factory=list)
    breach_detected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass
class BreachReport:
    """Generated breach report for DPDP Board notification."""
    report_id: str
    generated_at: datetime
    breach_scope: BreachScope
    records_flagged: int
    notifications_queued: int
    retro_eval_jobs_frozen: int
    data_categories: list[str]
    recommended_actions: list[str]
    severity: str


# ── Primary breach response function ─────────────────────────────────────────

async def breach_response(
    application_id: str | None = None,
    time_range_start: datetime | None = None,
    time_range_end: datetime | None = None,
    severity: str = "HIGH",
    triggered_by: str = "system",
) -> BreachReport:
    """
    Activate DPDP breach response for an application or time range.

    This is the Python-layer wrapper around the break_glass() PostgreSQL
    procedure. It provides additional logic:
      - Freezes pending retro-eval Celery tasks for affected records
      - Generates a structured BreachReport for regulatory notification
      - Logs the full breach event with all context

    Must provide EITHER application_id OR time_range_start+time_range_end.

    Args:
        application_id: Single application UUID string to flag.
        time_range_start: Start of time range for bulk flagging.
        time_range_end: End of time range for bulk flagging.
        severity: LOW, MEDIUM, HIGH, or CRITICAL.
        triggered_by: Who triggered the breach response (user ID or 'system').

    Returns:
        BreachReport with full scope and recommended actions.

    Raises:
        ValueError: If neither application_id nor time_range is provided.
    """
    if application_id is None and (
        time_range_start is None or time_range_end is None
    ):
        raise ValueError(
            "Must provide either application_id or both time_range_start and time_range_end."
        )

    breach_detected_at = datetime.now(timezone.utc)

    logger.critical(
        "breach.response.activated",
        application_id=application_id,
        time_range_start=time_range_start.isoformat() if time_range_start else None,
        time_range_end=time_range_end.isoformat() if time_range_end else None,
        severity=severity,
        triggered_by=triggered_by,
    )

    # Step 1: Call the PostgreSQL break_glass procedure
    records_flagged, notifications_queued = await _call_break_glass_procedure(
        application_id=application_id,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
    )

    # Step 2: Freeze pending retro-eval jobs for affected records
    frozen_count = await _freeze_retro_eval_jobs(
        application_id=application_id,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
    )

    # Step 3: Determine affected application IDs and data categories
    affected_ids = await _get_affected_application_ids(
        application_id=application_id,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
    )
    data_categories = _assess_data_categories(severity)

    # Step 4: Queue DPDP Board notification
    await _queue_board_notification(
        records_flagged=records_flagged,
        affected_ids=affected_ids,
        severity=severity,
        breach_detected_at=breach_detected_at,
    )

    # Step 5: Generate breach report
    import uuid  # noqa: PLC0415
    report = BreachReport(
        report_id=str(uuid.uuid4()),
        generated_at=breach_detected_at,
        breach_scope=BreachScope(
            application_ids=affected_ids,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            estimated_records_affected=records_flagged,
            data_categories_affected=data_categories,
            breach_detected_at=breach_detected_at,
        ),
        records_flagged=records_flagged,
        notifications_queued=notifications_queued,
        retro_eval_jobs_frozen=frozen_count,
        data_categories=data_categories,
        recommended_actions=_get_recommended_actions(severity),
        severity=severity,
    )

    logger.critical(
        "breach.response.completed",
        report_id=report.report_id,
        records_flagged=records_flagged,
        notifications_queued=notifications_queued,
        frozen_count=frozen_count,
        severity=severity,
    )

    # Record Prometheus metric
    try:
        from observability.metrics import DPDP_BREACH_FLAGS_TOTAL  # noqa: PLC0415
        DPDP_BREACH_FLAGS_TOTAL.labels(is_demo="false").inc(records_flagged)
    except Exception:
        pass

    return report


# ── PostgreSQL procedure call ─────────────────────────────────────────────────

async def _call_break_glass_procedure(
    application_id: str | None,
    time_range_start: datetime | None,
    time_range_end: datetime | None,
) -> tuple[int, int]:
    """
    Call the break_glass() PostgreSQL stored procedure.

    Returns:
        Tuple of (records_flagged, notifications_queued).
    """
    from db.session import get_session_context  # noqa: PLC0415
    from sqlalchemy import text  # noqa: PLC0415

    async with get_session_context() as db:
        if application_id is not None:
            result = await db.execute(
                text("SELECT records_flagged, notifications_queued FROM break_glass(:app_id)"),
                {"app_id": application_id},
            )
        else:
            result = await db.execute(
                text(
                    "SELECT application_ids_affected, records_flagged, notifications_queued "
                    "FROM break_glass_range(:start_time, :end_time)"
                ),
                {
                    "start_time": time_range_start,
                    "end_time": time_range_end,
                },
            )
        row = result.fetchone()
        await db.commit()

        if row is None:
            return 0, 0

        if application_id is not None:
            return int(row[0] or 0), int(row[1] or 0)
        else:
            # break_glass_range returns 3 columns
            return int(row[1] or 0), int(row[2] or 0)


# ── Retro-eval job freezing ───────────────────────────────────────────────────

async def _freeze_retro_eval_jobs(
    application_id: str | None,
    time_range_start: datetime | None,
    time_range_end: datetime | None,
) -> int:
    """
    Revoke pending retro-eval Celery tasks for affected applications.

    Uses Celery's task revocation to prevent further processing of
    potentially compromised data while breach investigation is underway.

    Returns:
        Number of tasks revoked.
    """
    frozen = 0
    try:
        import redis as redis_lib  # noqa: PLC0415
        import os  # noqa: PLC0415
        import json  # noqa: PLC0415

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = redis_lib.from_url(redis_url, decode_responses=True)

        # Get all retro_eval queue messages and filter by application_id
        # This is a best-effort operation — we scan the queue for matching tasks
        queue_length = r.llen("retro_eval")
        tasks_to_revoke = []

        for i in range(min(queue_length, 10000)):
            try:
                raw = r.lindex("retro_eval", i)
                if raw:
                    task_data = json.loads(raw)
                    task_kwargs = task_data.get("kwargs", {})
                    task_app_id = task_kwargs.get("application_id", "")
                    if application_id and task_app_id == application_id:
                        task_id = task_data.get("id")
                        if task_id:
                            tasks_to_revoke.append(task_id)
            except Exception:
                continue

        if tasks_to_revoke:
            from workers.celery_app import app as celery_app  # noqa: PLC0415
            for task_id in tasks_to_revoke:
                celery_app.control.revoke(task_id, terminate=False)
                frozen += 1

        logger.info(
            "breach.retro_eval.frozen",
            frozen_count=frozen,
            application_id=application_id,
        )

    except Exception as exc:
        logger.warning(
            "breach.retro_eval.freeze_failed",
            error=str(exc),
        )

    return frozen


# ── Affected application lookup ───────────────────────────────────────────────

async def _get_affected_application_ids(
    application_id: str | None,
    time_range_start: datetime | None,
    time_range_end: datetime | None,
) -> list[str]:
    """Get list of affected application IDs for the breach report."""
    if application_id:
        return [application_id]

    from db.session import get_session_context  # noqa: PLC0415
    from models.audit_record import AuditRecord  # noqa: PLC0415
    from sqlalchemy import select, distinct  # noqa: PLC0415

    async with get_session_context() as db:
        stmt = (
            select(distinct(AuditRecord.application_id))
            .where(
                AuditRecord.written_at >= time_range_start,
                AuditRecord.written_at <= time_range_end,
            )
            .limit(1000)  # Cap at 1000 for report size
        )
        result = await db.execute(stmt)
        return [str(row[0]) for row in result.fetchall()]


# ── Report helpers ────────────────────────────────────────────────────────────

def _assess_data_categories(severity: str) -> list[str]:
    """Return data categories likely affected based on severity."""
    base = ["Application identifiers", "Loan application details", "Decision outcomes"]
    if severity in ("HIGH", "CRITICAL"):
        base.extend([
            "Encrypted personal data payload (AES-256-GCM)",
            "PAN HMAC (not plaintext — low risk)",
            "Income and financial details",
        ])
    if severity == "CRITICAL":
        base.extend([
            "Document metadata",
            "KYC status information",
        ])
    return base


def _get_recommended_actions(severity: str) -> list[str]:
    """Return recommended post-breach actions based on severity."""
    actions = [
        "Immediately review breach scope using audit_records.breach_flag query",
        "Notify affected applicants via notification_outbox (automated — verify delivery)",
        "Assess whether AES encryption key (AES_KEY) needs rotation",
        "Review access logs for unauthorized database access",
    ]
    if severity in ("HIGH", "CRITICAL"):
        actions.extend([
            "MANDATORY: Notify Data Protection Board within 72 hours (DPDP Act S.8)",
            "Engage legal counsel immediately",
            "Rotate SERVER_HMAC_KEY and AES_KEY using scripts/rotate_secrets.sh",
            "Consider suspending new application intake during investigation",
        ])
    if severity == "CRITICAL":
        actions.extend([
            "CRITICAL: Consider notifying law enforcement if fraud is suspected",
            "Preserve all server logs for forensic investigation",
            "Do not alter or delete any database records until legal review",
        ])
    return actions


async def _queue_board_notification(
    records_flagged: int,
    affected_ids: list[str],
    severity: str,
    breach_detected_at: datetime,
) -> None:
    """Queue a BREACH_ALERT notification for the DPDP Board contact email."""
    import os  # noqa: PLC0415
    board_email = os.environ.get("DPDP_BOARD_NOTIFICATION_EMAIL", "")
    if not board_email:
        logger.warning(
            "breach.board_notification.skipped",
            reason="DPDP_BOARD_NOTIFICATION_EMAIL not configured",
        )
        return

    from db.session import get_session_context  # noqa: PLC0415
    from models.notification_outbox import (  # noqa: PLC0415
        NotificationChannel,
        NotificationOutbox,
        NotificationStatus,
        NotificationType,
    )
    import uuid  # noqa: PLC0415

    async with get_session_context() as db:
        notification = NotificationOutbox(
            id=uuid.uuid4(),
            notification_type=NotificationType.BREACH_ALERT,
            channel=NotificationChannel.EMAIL,
            recipient_email=board_email,
            payload={
                "breach_detected_at": breach_detected_at.isoformat(),
                "records_flagged": records_flagged,
                "affected_applications_count": len(affected_ids),
                "severity": severity,
                "data_fiduciary": "ComplianceLoop NBFC",
                "message": (
                    f"A personal data breach has been detected affecting "
                    f"{records_flagged} records. Severity: {severity}. "
                    "Formal notification to follow within 72 hours per DPDP Act Section 8."
                ),
            },
            status=NotificationStatus.PENDING,
            is_demo=False,
        )
        db.add(notification)
        await db.commit()