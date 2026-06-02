"""
ComplianceLoop — Security Module
=================================
Provides cryptographic primitives used across the entire system:

  - AES-256-GCM encryption/decryption for PII payloads (payload_encrypted column)
  - HMAC-SHA256 for audit record signing and verification
  - PAN HMAC hashing (separate key from audit HMAC — by design)
  - Secrets loading from environment / HashiCorp Vault

Design rules enforced here:
  1. PAN_HMAC_KEY must differ from SERVER_HMAC_KEY — validated at import time
  2. All keys are loaded once and cached; never re-read per-request
  3. No plaintext PAN or Aadhaar ever appears in logs or return values
  4. Constant-time comparison used for all HMAC verification to prevent timing attacks
"""

from security.encryption import (
    decrypt_payload,
    encrypt_payload,
)
from security.hmac_utils import (
    compute_record_hmac,
    compute_sha256,
    verify_record_hmac,
)
from security.pan_handler import (
    PAN_FORMAT_REGEX,
    hmac_pan,
    validate_pan_format,
    verify_pan_hmac,
)
from security.secrets_loader import get_secret, load_secrets

__all__ = [
    # Encryption
    "encrypt_payload",
    "decrypt_payload",
    # HMAC / hashing
    "compute_sha256",
    "compute_record_hmac",
    "verify_record_hmac",
    # PAN
    "hmac_pan",
    "verify_pan_hmac",
    "validate_pan_format",
    "PAN_FORMAT_REGEX",
    # Secrets
    "load_secrets",
    "get_secret",
]