"""
ComplianceLoop — Audit Module
==============================
Tamper-evident audit system for compliance evidence.

The audit module enforces ADR-003: audit record written BEFORE API responds.

Components:
  - writer.py    : AuditWriter LangGraph node — pre-response Postgres write
  - hasher.py    : SHA-256 + HMAC-SHA256 computation for audit fields
  - verifier.py  : Integrity verification for regulator queries
  - s3_uploader  : Async MinIO payload upload with retry

Core guarantee:
  Every pipeline decision has a tamper-evident audit record in PostgreSQL
  before the HTTP response leaves the server. The record contains:
    - agent_outputs_hash : SHA-256 of canonical JSON of all 5 AgentResults
    - record_hmac        : HMAC-SHA256 binding hash + decision metadata + key
  These two fields together prove the record is intact (hash) and authentic
  (HMAC — only this server with SERVER_HMAC_KEY can produce it).

Usage in pipeline (pipeline/graph.py):
    from audit.writer import AuditWriter
    writer = AuditWriter()
    graph.add_node("audit", writer.write_node)
    graph.add_edge("decision", "audit")

Usage in API (GET /v1/applications/{id}/audit):
    from audit.verifier import verify_by_decision_id
    result = await verify_by_decision_id(decision_id=str(decision_id))
    return result.to_report_dict()
"""

from audit.writer import AuditWriter
from audit.hasher import (
    compute_agent_outputs_hash,
    compute_audit_hmac,
    compute_payload_s3_key,
    verify_audit_record_integrity,
)
from audit.verifier import (
    VerificationResult,
    verify_by_decision_id,
    verify_by_application_id,
)
from audit.s3_uploader import (
    upload_audit_payload,
    retry_pending_uploads,
)

__all__ = [
    # Writer
    "AuditWriter",
    # Hasher
    "compute_agent_outputs_hash",
    "compute_audit_hmac",
    "compute_payload_s3_key",
    "verify_audit_record_integrity",
    # Verifier
    "VerificationResult",
    "verify_by_decision_id",
    "verify_by_application_id",
    # S3 uploader
    "upload_audit_payload",
    "retry_pending_uploads",
]