"""
ComplianceLoop — Audit Hasher
==============================
Provides the exact cryptographic operations used to produce and verify
audit record integrity fields.

This module is the single source of truth for:
  - How agent_outputs_hash is computed (SHA-256 of canonical JSON)
  - How record_hmac is computed (HMAC-SHA256 over pipe-separated fields)
  - The canonical message format that must be reproduced identically for
    verification (documented in docs/runbooks/regulator_audit_response.md)

Relationship to security/hmac_utils.py:
  security/hmac_utils.py is the low-level cryptographic primitive layer.
  audit/hasher.py is the audit-domain wrapper that applies those primitives
  with the exact field ordering and serialisation required for audit records.
  All actual crypto (HMAC, SHA-256, canonical JSON) lives in security/hmac_utils.py.
  This module imports from there and adds audit-specific logic on top.

Wire format for record_hmac message:
  "{agent_outputs_hash}|{decision_id}|{guideline_version_id}|{written_at}"
  - Pipe separator (|) — none of these fields can contain a pipe character
  - written_at is ISO 8601 UTC with microseconds: "2026-06-01T12:00:00.000000+00:00"
  - All fields are strings — UUIDs as hyphenated lowercase hex strings

This exact format is documented in:
  docs/runbooks/regulator_audit_response.md
  docs/decisions/ADR-003-audit-before-response.md
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from security.hmac_utils import (
    canonical_json,
    compute_record_hmac,
    compute_sha256,
    hash_agent_outputs,
    verify_record_hmac,
    verify_sha256,
)


# ── Public audit hashing API ──────────────────────────────────────────────────

def compute_agent_outputs_hash(agent_outputs: dict[str, Any]) -> str:
    """
    Compute the agent_outputs_hash for an audit record.

    This is the SHA-256 of the canonical JSON serialisation of all five
    AgentResult objects. Canonical JSON means: keys sorted alphabetically,
    no whitespace, ASCII-only, consistent datetime serialisation.

    Args:
        agent_outputs: Dict mapping agent name → AgentResult dict.
                       Must contain results for all five agents:
                       {document, sanctions, temporal, transaction, rag}
                       Missing agent keys produce a different hash from
                       a complete set — this is intentional and detectable.

    Returns:
        64-character lowercase hex SHA-256 digest.

    Raises:
        ValueError: If agent_outputs is empty.
    """
    return hash_agent_outputs(agent_outputs)


def compute_audit_hmac(
    agent_outputs_hash: str,
    decision_id: str,
    guideline_version_id: str,
    written_at: datetime,
) -> str:
    """
    Compute the record_hmac for an audit record.

    Binds the content hash to the decision metadata using SERVER_HMAC_KEY.
    This proves the record was produced by this server (key holder) and
    that the bound fields have not been tampered with.

    Args:
        agent_outputs_hash: 64-char hex SHA-256 from compute_agent_outputs_hash().
        decision_id: UUID string of the Decision record (lowercase with hyphens).
        guideline_version_id: UUID string of the GuidelineVersion used.
        written_at: Exact UTC datetime when the audit record was written.
                    Must be the same value stored in audit_records.written_at.
                    Any difference in datetime formatting produces a different HMAC.

    Returns:
        64-character lowercase hex HMAC-SHA256 digest.

    Raises:
        RuntimeError: If SERVER_HMAC_KEY is not configured.
    """
    written_at_str = _serialise_written_at(written_at)
    return compute_record_hmac(
        agent_outputs_hash=agent_outputs_hash,
        decision_id=str(decision_id),
        guideline_version_id=str(guideline_version_id),
        written_at=written_at_str,
    )


def verify_audit_record_integrity(
    stored_agent_outputs_hash: str,
    stored_record_hmac: str,
    agent_outputs: dict[str, Any],
    decision_id: str,
    guideline_version_id: str,
    written_at: datetime,
) -> tuple[bool, str]:
    """
    Verify the integrity of a stored audit record.

    Recomputes both the SHA-256 hash of agent outputs and the HMAC,
    then compares against stored values using constant-time comparison.

    This is the function called by audit/verifier.py and by
    scripts/verify_audit_record.sh.

    Args:
        stored_agent_outputs_hash: Value from audit_records.agent_outputs_hash.
        stored_record_hmac: Value from audit_records.record_hmac.
        agent_outputs: Decrypted agent outputs from MinIO payload.
        decision_id: UUID string from audit_records.decision_id.
        guideline_version_id: UUID string from audit_records.guideline_version_id.
        written_at: Datetime from audit_records.written_at.

    Returns:
        Tuple of (is_valid: bool, failure_reason: str).
        failure_reason is empty string on success.
    """
    # Step 1: Verify agent outputs hash
    recomputed_hash = compute_agent_outputs_hash(agent_outputs)
    if not verify_sha256(
        canonical_json(agent_outputs),
        stored_agent_outputs_hash,
    ):
        return False, (
            f"agent_outputs_hash mismatch. "
            f"Stored: {stored_agent_outputs_hash[:16]}... "
            f"Recomputed: {recomputed_hash[:16]}... "
            "The agent outputs have been tampered with."
        )

    # Step 2: Verify record HMAC
    written_at_str = _serialise_written_at(written_at)
    hmac_valid = verify_record_hmac(
        stored_hmac=stored_record_hmac,
        agent_outputs_hash=recomputed_hash,
        decision_id=str(decision_id),
        guideline_version_id=str(guideline_version_id),
        written_at=written_at_str,
    )

    if not hmac_valid:
        return False, (
            "record_hmac verification failed. "
            "The audit record metadata (decision_id, guideline_version_id, or "
            "written_at) may have been tampered with, or the wrong signing key "
            "is being used."
        )

    return True, ""


def compute_payload_s3_key(decision_id: str, written_at: datetime) -> str:
    """
    Compute the MinIO object key for an audit payload.

    Format: audit/{year}/{month}/{decision_id}.json.enc
    Example: audit/2026/06/550e8400-e29b-41d4-a716-446655440000.json.enc

    Args:
        decision_id: UUID string of the decision.
        written_at: UTC datetime of the audit write.

    Returns:
        MinIO object key string.
    """
    year = written_at.strftime("%Y")
    month = written_at.strftime("%m")
    return f"audit/{year}/{month}/{decision_id}.json.enc"


# ── Internal helpers ──────────────────────────────────────────────────────────

def _serialise_written_at(written_at: datetime) -> str:
    """
    Serialise written_at datetime to the canonical string format used in HMAC.

    Format: ISO 8601 with UTC timezone and microseconds.
    Example: "2026-06-01T12:00:00.000000+00:00"

    CRITICAL: This format must be reproduced identically for HMAC verification.
    Any deviation (missing timezone, different precision) produces a different
    HMAC and will cause verification to fail.

    Args:
        written_at: UTC datetime. If naive (no tzinfo), treated as UTC.

    Returns:
        ISO 8601 string with UTC timezone offset (+00:00).
    """
    if written_at.tzinfo is None:
        written_at = written_at.replace(tzinfo=timezone.utc)
    # Ensure UTC
    written_at_utc = written_at.astimezone(timezone.utc)
    return written_at_utc.isoformat()