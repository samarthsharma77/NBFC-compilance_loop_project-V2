"""
ComplianceLoop — Audit Writer
==============================
The AuditWriter writes the tamper-evident audit record to PostgreSQL
BEFORE the LangGraph pipeline returns its result to the API layer.

This is the most critical design decision in the system (ADR-003):
  "The audit record is written before the HTTP response is returned."

Why pre-response write?
  If we write after responding, a crash between the API response and the
  audit write leaves us with a decision that has no compliance evidence.
  In a regulatory audit, we cannot prove the decision was made correctly.

  By writing BEFORE responding, the compliance evidence exists even if:
    - The client's connection drops
    - The server crashes after writing but before responding (client gets
      a timeout, retries, gets a cached result — the audit record exists)
    - A downstream LOS webhook fails
    - The MinIO upload fails (Postgres is source of truth)

LangGraph integration:
  AuditWriter.write_node() is the final node in the LangGraph StateGraph,
  placed between the decision_node and the outcome_router edge.

  graph.add_node("audit", AuditWriter().write_node)
  graph.add_edge("decision", "audit")
  graph.add_conditional_edges("audit", route_outcome, {...})

  The write_node receives the full ComplianceState (which includes
  the decision outcome, confidence, agent outputs, and rationale chain)
  and writes the audit_record before returning the updated state.

Failure handling:
  If the PostgreSQL write fails (DB unavailable), write_node raises.
  LangGraph propagates this as a pipeline error. The API returns HTTP 503.
  No decision is returned to the client. This is correct — we cannot
  give a compliance decision without being able to prove it was made.

  If the MinIO upload fails (after Postgres write succeeds), write_node
  still returns successfully. The audit_record.payload_s3_uploaded = False.
  The retry_pending_uploads Celery task handles MinIO eventually.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

import structlog

from audit.hasher import (
    compute_agent_outputs_hash,
    compute_audit_hmac,
    compute_payload_s3_key,
)

if TYPE_CHECKING:
    pass  # pipeline.state imports avoided here to prevent circular deps

logger = structlog.get_logger(__name__)


class AuditWriter:
    """
    Writes the pre-response audit record for each pipeline run.

    Instantiated once per pipeline graph build and reused across runs.
    The write_node method is registered as the "audit" node in LangGraph.
    """

    async def write_node(self, state: dict[str, Any]) -> dict[str, Any]:
        """
        LangGraph node: write audit record to PostgreSQL (blocking) and
        queue MinIO upload (non-blocking).

        This method is called as the last LangGraph node before the
        outcome router edge. It MUST complete successfully before the
        pipeline can return a result.

        Args:
            state: ComplianceState dict from LangGraph.
                   Must contain: decision, confidence, composite_score,
                   agent_outputs (all 5), rationale_chain, outcome_signals,
                   guideline_version_id, application_id, run_number,
                   is_retro_eval, is_demo.

        Returns:
            Updated state with audit_id set.

        Raises:
            RuntimeError: If PostgreSQL write fails (pipeline aborts,
                         API returns 503, no decision returned to client).
        """
        from observability.metrics import (  # noqa: PLC0415
            AUDIT_WRITE_DURATION,
            AUDIT_WRITE_ERRORS_TOTAL,
        )
        import time  # noqa: PLC0415

        start = time.monotonic()
        is_demo = state.get("is_demo", False)
        demo_str = str(is_demo).lower()

        try:
            audit_id = await self._write_audit_record(state)
            duration_s = time.monotonic() - start

            AUDIT_WRITE_DURATION.labels(
                status="success", is_demo=demo_str
            ).observe(duration_s)

            logger.info(
                "audit.written",
                audit_id=str(audit_id),
                decision_id=state.get("decision_id"),
                application_id=state.get("application_id"),
                outcome=state.get("decision"),
                duration_ms=int(duration_s * 1000),
                is_demo=is_demo,
            )

            # Return updated state with audit_id
            return {**state, "audit_id": str(audit_id)}

        except Exception as exc:
            duration_s = time.monotonic() - start

            AUDIT_WRITE_DURATION.labels(
                status="postgres_error", is_demo=demo_str
            ).observe(duration_s)
            AUDIT_WRITE_ERRORS_TOTAL.labels(
                error_type="postgres", is_demo=demo_str
            ).inc()

            logger.error(
                "audit.write_failed",
                application_id=state.get("application_id"),
                decision_id=state.get("decision_id"),
                error=str(exc),
            )

            # Re-raise — pipeline must abort if audit write fails
            raise RuntimeError(
                f"Audit record write failed: {exc}. "
                "The compliance decision cannot be returned without a persisted "
                "audit record. This is a system error — check database connectivity."
            ) from exc

    async def _write_audit_record(self, state: dict[str, Any]) -> uuid.UUID:
        """
        Core audit write logic:
          1. Compute agent_outputs_hash (SHA-256 of canonical JSON)
          2. Record written_at (server time — not client time)
          3. Compute record_hmac (HMAC-SHA256 binding hash + metadata)
          4. INSERT audit_record to PostgreSQL (blocking commit)
          5. Enqueue MinIO upload as background task (non-blocking)

        Args:
            state: ComplianceState dict.

        Returns:
            UUID of the created audit_record.

        Raises:
            Any DB error — propagated to write_node for handling.
        """
        from db.session import get_session_context  # noqa: PLC0415
        from models.audit_record import AuditRecord  # noqa: PLC0415
        from models.guideline_version import GuidelineVersion  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        # Extract required state fields
        decision_id = str(state["decision_id"])
        application_id = str(state["application_id"])
        guideline_version_id = str(state["guideline_version_id"])
        agent_outputs = _extract_agent_outputs(state)
        is_demo = bool(state.get("is_demo", False))

        # Server-set written_at — NOT from client
        written_at = datetime.now(timezone.utc)

        # Step 1: Compute content hash
        agent_outputs_hash = compute_agent_outputs_hash(agent_outputs)

        # Step 2: Compute HMAC
        record_hmac = compute_audit_hmac(
            agent_outputs_hash=agent_outputs_hash,
            decision_id=decision_id,
            guideline_version_id=guideline_version_id,
            written_at=written_at,
        )

        # Step 3: Compute S3 key (before DB write so it's in the record)
        s3_key = compute_payload_s3_key(
            decision_id=decision_id,
            written_at=written_at,
        )

        # Step 4: Get affected_agent_tags from guideline version
        affected_agent_tags = await _get_affected_agent_tags(
            guideline_version_id=guideline_version_id,
            is_demo=is_demo,
        )

        # Step 5: INSERT audit_record (synchronous, blocking commit)
        audit_record_id = uuid.uuid4()

        async with get_session_context() as db:
            record = AuditRecord(
                id=audit_record_id,
                decision_id=uuid.UUID(decision_id),
                application_id=uuid.UUID(application_id),
                guideline_version_id=uuid.UUID(guideline_version_id),
                affected_agent_tags=affected_agent_tags,
                agent_outputs_hash=agent_outputs_hash,
                record_hmac=record_hmac,
                payload_s3_key=s3_key,
                payload_s3_uploaded=False,  # Will be set True after MinIO upload
                written_at=written_at,
                breach_flag=False,
                is_demo=is_demo,
            )
            db.add(record)
            await db.commit()

        logger.debug(
            "audit.postgres.committed",
            audit_id=str(audit_record_id),
            written_at=written_at.isoformat(),
            agent_outputs_hash=agent_outputs_hash[:16] + "...",
        )

        # Step 6: Enqueue MinIO upload (non-blocking — runs after response)
        _schedule_minio_upload(
            decision_id=decision_id,
            application_id=application_id,
            guideline_version_id=guideline_version_id,
            written_at=written_at,
            agent_outputs=agent_outputs,
            outcome=state.get("decision", ""),
            confidence=float(state.get("confidence", 0.0)),
            rationale_chain=state.get("rationale_chain", []),
            s3_key=s3_key,
            is_demo=is_demo,
        )

        return audit_record_id


# ── MinIO upload scheduling ───────────────────────────────────────────────────

def _schedule_minio_upload(
    decision_id: str,
    application_id: str,
    guideline_version_id: str,
    written_at: datetime,
    agent_outputs: dict[str, Any],
    outcome: str,
    confidence: float,
    rationale_chain: list[dict[str, Any]],
    s3_key: str,
    is_demo: bool,
) -> None:
    """
    Schedule the MinIO payload upload as a Celery task.

    This is called AFTER the Postgres commit, so the audit record
    already exists in the DB with payload_s3_uploaded=False.

    If Celery is not available (e.g. in tests), schedules as an
    asyncio background task instead.
    """
    try:
        from workers.celery_app import app as celery_app  # noqa: PLC0415
        celery_app.send_task(
            "audit.s3_uploader.upload_audit_payload_task",
            kwargs={
                "decision_id": decision_id,
                "application_id": application_id,
                "guideline_version_id": guideline_version_id,
                "written_at": written_at.isoformat(),
                "agent_outputs": agent_outputs,
                "outcome": outcome,
                "confidence": confidence,
                "rationale_chain": rationale_chain,
                "s3_key": s3_key,
            },
            queue="calibration",  # Low-priority queue — not time-critical
        )
    except Exception as exc:
        # If Celery task dispatch fails, log and continue.
        # The retry_pending_uploads Beat task will pick this up.
        logger.warning(
            "audit.minio.task_dispatch_failed",
            decision_id=decision_id,
            error=str(exc),
        )


# ── State extraction helpers ──────────────────────────────────────────────────

def _extract_agent_outputs(state: dict[str, Any]) -> dict[str, Any]:
    """
    Extract all five agent results from the ComplianceState.

    The five keys in ComplianceState are:
      document_result, sanctions_result, temporal_result,
      transaction_result, rag_context

    Normalised to a flat dict for hashing:
      {document: {...}, sanctions: {...}, temporal: {...},
       transaction: {...}, rag: {...}}

    Missing agent results are recorded as None — this produces a
    different hash from a complete set, making incomplete runs detectable.

    Args:
        state: ComplianceState dict from LangGraph.

    Returns:
        Dict with five agent result keys.
    """
    return {
        "document":    _serialise_agent_result(state.get("document_result")),
        "sanctions":   _serialise_agent_result(state.get("sanctions_result")),
        "temporal":    _serialise_agent_result(state.get("temporal_result")),
        "transaction": _serialise_agent_result(state.get("transaction_result")),
        "rag":         _serialise_agent_result(state.get("rag_context")),
    }


def _serialise_agent_result(result: Any) -> dict[str, Any] | None:
    """
    Convert an AgentResult or RAGContext object to a plain dict.

    Handles both dataclass and dict representations since LangGraph
    state values may be either depending on how the agent sets them.

    Args:
        result: AgentResult dataclass instance, dict, or None.

    Returns:
        Plain dict suitable for JSON serialisation, or None.
    """
    if result is None:
        return None
    if isinstance(result, dict):
        return result
    # Dataclass — convert via __dict__ or dataclasses.asdict
    try:
        import dataclasses  # noqa: PLC0415
        if dataclasses.is_dataclass(result):
            return dataclasses.asdict(result)
    except Exception:
        pass
    # Fallback: try __dict__
    return vars(result) if hasattr(result, "__dict__") else {"raw": str(result)}


async def _get_affected_agent_tags(
    guideline_version_id: str,
    is_demo: bool,
) -> list[str]:
    """
    Retrieve affected_agent_tags from the GuidelineVersion record.

    These tags are stored on the audit_record to enable the retro-eval
    GIN-indexed filter query:
      WHERE affected_agent_tags && ARRAY['temporal']

    Falls back to ["document", "sanctions", "temporal", "transaction", "rag"]
    (all agents) if the guideline version cannot be found — ensures the
    retro-eval filter will always include this record in the worst case.

    Args:
        guideline_version_id: UUID string.
        is_demo: Demo context flag.

    Returns:
        List of agent tag strings.
    """
    try:
        import uuid  # noqa: PLC0415
        from db.session import get_session_context  # noqa: PLC0415
        from models.guideline_version import GuidelineVersion  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        async with get_session_context(is_demo=is_demo) as db:
            stmt = select(GuidelineVersion.affected_agent_tags).where(
                GuidelineVersion.id == uuid.UUID(guideline_version_id)
            )
            result = await db.execute(stmt)
            row = result.scalar_one_or_none()

        if row is not None and row:
            return list(row)

    except Exception as exc:
        logger.warning(
            "audit.guideline_tags.fetch_failed",
            guideline_version_id=guideline_version_id,
            error=str(exc),
        )

    # Fallback: tag all agents (conservative — includes this record in all retro-evals)
    return ["document", "sanctions", "temporal", "transaction", "rag"]