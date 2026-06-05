"""
ComplianceLoop — DPDP Compliance Module
=========================================
Operational controls for Digital Personal Data Protection Act 2023 compliance.

Obligations covered:
  - Notice & Consent    : consent_manager.py
  - Storage Limitation  : retention_enforcer.py
  - Breach Response     : breach_response.py
  - Data Subject Rights : data_subject_handler.py

All obligations are enforced as operational controls, not policy documents.
The consent gate is a hard API middleware check — no bypass exists.
Retention wipes are automated via Celery Beat.
Breach response triggers the PostgreSQL break_glass() procedure.
"""

from dpdp.consent_manager import (
    ConsentValidationResult,
    activate_consent_version,
    get_active_consent_version,
    get_consent_version_text,
    validate_consent,
)
from dpdp.retention_enforcer import (
    compute_retention_expiry,
    run_retention_wipe,
    wipe_minio_payloads,
)
from dpdp.breach_response import (
    BreachReport,
    BreachScope,
    breach_response,
)
from dpdp.data_subject_handler import (
    DataAccessResponse,
    ErasureResponse,
    handle_access_request,
    handle_consent_withdrawal,
    handle_erasure_request,
)

__all__ = [
    # Consent
    "ConsentValidationResult",
    "validate_consent",
    "get_active_consent_version",
    "activate_consent_version",
    "get_consent_version_text",
    # Retention
    "run_retention_wipe",
    "compute_retention_expiry",
    "wipe_minio_payloads",
    # Breach response
    "BreachScope",
    "BreachReport",
    "breach_response",
    # Data subject rights
    "DataAccessResponse",
    "ErasureResponse",
    "handle_access_request",
    "handle_erasure_request",
    "handle_consent_withdrawal",
]