"""
ComplianceLoop — HMAC & SHA-256 Utilities
==========================================
Provides the cryptographic integrity functions used by the audit system.

Two distinct operations:

1. SHA-256 hash of agent outputs (agent_outputs_hash column):
   - Input: canonical JSON of all five AgentResult objects
   - Output: 64-char hex string
   - Purpose: content fingerprint — proves the agent outputs haven't changed

2. HMAC-SHA256 of the audit record (record_hmac column):
   - Input: agent_outputs_hash + decision_id + guideline_version_id + written_at
   - Key: SERVER_HMAC_KEY (separate from PAN_HMAC_KEY)
   - Output: 64-char hex string
   - Purpose: authenticity proof — proves this record was produced by THIS server
              with THIS key. Cannot be forged without the key.

Verification protocol (for regulator queries):
  1. Retrieve audit_record from PostgreSQL
  2. Download encrypted payload from MinIO, decrypt
  3. Recompute SHA-256 of agent_outputs → compare with agent_outputs_hash
  4. Recompute HMAC → compare with record_hmac
  5. Both match = record is intact and authentic

Key management:
  - SERVER_HMAC_KEY is loaded from env / Vault
  - On key rotation: old key is kept as SERVER_HMAC_KEY_PREVIOUS
  - verify_record_hmac() tries current key first, then previous key
  - This gives a 90-day overlap window to verify old records
    during the rotation period (see scripts/rotate_secrets.sh)

Security properties:
  - HMAC-SHA256 with 256-bit key: collision resistance, preimage resistance
  - hmac.compare_digest() for constant-time comparison (prevents timing attacks)
  - Keys never appear in logs, error messages, or return values
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime
from typing import Any, Final

# ── Constants ─────────────────────────────────────────────────────────────────

_HASH_ALGORITHM: Final[str] = "sha256"
_EXPECTED_HASH_LENGTH: Final[int] = 64  # SHA-256 hex digest length


# ── Key loading ───────────────────────────────────────────────────────────────

def _load_hmac_key(env_var: str) -> bytes:
    """
    Load and validate an HMAC key from an environment variable.

    Args:
        env_var: Name of the environment variable to read.

    Returns:
        32-byte key.

    Raises:
        RuntimeError: If variable is missing, not valid hex, or wrong length.
    """
    raw = os.environ.get(env_var, "")
    if not raw:
        raise RuntimeError(
            f"{env_var} environment variable is not set. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        key_bytes = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError(
            f"{env_var} is not valid hex: {exc}"
        ) from exc

    if len(key_bytes) != 32:
        raise RuntimeError(
            f"{env_var} must be exactly 32 bytes (64 hex chars). "
            f"Got {len(key_bytes)} bytes."
        )
    return key_bytes


# Lazy singletons
_server_hmac_key: bytes | None = None
_server_hmac_key_previous: bytes | None = None


def _get_server_hmac_key() -> bytes:
    """Return cached SERVER_HMAC_KEY, loading on first call."""
    global _server_hmac_key  # noqa: PLW0603
    if _server_hmac_key is None:
        _server_hmac_key = _load_hmac_key("SERVER_HMAC_KEY")
    return _server_hmac_key


def _get_previous_hmac_key() -> bytes | None:
    """
    Return cached SERVER_HMAC_KEY_PREVIOUS if set (used during key rotation).
    Returns None if the env var is not set (no rotation in progress).
    """
    global _server_hmac_key_previous  # noqa: PLW0603
    if _server_hmac_key_previous is None:
        prev = os.environ.get("SERVER_HMAC_KEY_PREVIOUS", "")
        if not prev:
            return None
        try:
            _server_hmac_key_previous = bytes.fromhex(prev)
        except ValueError:
            return None
    return _server_hmac_key_previous


def invalidate_key_cache() -> None:
    """
    Clear cached HMAC keys so they are reloaded on next use.
    Called after key rotation to pick up new keys without restarting.
    Exported for use by secrets_loader and rotation scripts.
    """
    global _server_hmac_key, _server_hmac_key_previous  # noqa: PLW0603
    _server_hmac_key = None
    _server_hmac_key_previous = None


# ── SHA-256 hashing ───────────────────────────────────────────────────────────

def compute_sha256(data: bytes) -> str:
    """
    Compute SHA-256 hash of bytes and return as lowercase hex string.

    Used to hash the canonical JSON of all five AgentResult objects
    before storing in audit_records.agent_outputs_hash.

    Args:
        data: Bytes to hash. Must not be empty.

    Returns:
        64-character lowercase hex string.

    Raises:
        ValueError: If data is empty.
    """
    if not data:
        raise ValueError("Cannot hash empty data.")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    """
    Produce a canonical (deterministic) JSON encoding of an object.

    Standard json.dumps() does not guarantee key ordering consistency
    across Python versions or implementations. This function produces
    a UTF-8 encoded bytes representation with:
      - Keys sorted alphabetically (sort_keys=True)
      - No whitespace (separators=(',', ':'))
      - Non-ASCII characters escaped

    This is the function that must be used when producing data that
    will be SHA-256 hashed for the audit record — any difference in
    serialisation would produce a different hash.

    Args:
        obj: Any JSON-serialisable Python object.

    Returns:
        Canonical UTF-8 bytes.

    Raises:
        TypeError: If obj is not JSON-serialisable.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_json_default,
    ).encode("utf-8")


def _json_default(obj: Any) -> Any:
    """
    JSON serialisation fallback for non-standard types.
    Handles datetime, UUID, and Enum types commonly found in agent outputs.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    # UUID — import locally to avoid circular imports
    import uuid  # noqa: PLC0415
    if isinstance(obj, uuid.UUID):
        return str(obj)
    # Enum
    import enum  # noqa: PLC0415
    if isinstance(obj, enum.Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serialisable")


def hash_agent_outputs(agent_outputs: dict[str, Any]) -> str:
    """
    Produce the agent_outputs_hash for an audit record.

    Takes the dict of all five AgentResult objects (keyed by agent name),
    serialises it canonically, and returns the SHA-256 hex digest.

    This is the primary function called by audit/writer.py.

    Args:
        agent_outputs: Dict mapping agent name → AgentResult dict.
                       Example: {"document": {...}, "sanctions": {...}, ...}

    Returns:
        64-character hex SHA-256 digest.

    Raises:
        ValueError: If agent_outputs is empty.
    """
    if not agent_outputs:
        raise ValueError("agent_outputs must not be empty.")
    data = canonical_json(agent_outputs)
    return compute_sha256(data)


# ── HMAC-SHA256 signing ───────────────────────────────────────────────────────

def _build_hmac_message(
    agent_outputs_hash: str,
    decision_id: str,
    guideline_version_id: str,
    written_at: str,
) -> bytes:
    """
    Build the canonical message that is HMAC'd for an audit record.

    The message is a pipe-separated concatenation of all four fields.
    Pipe separator was chosen because none of these fields can contain '|':
      - agent_outputs_hash: hex chars only
      - decision_id: UUID (hex + hyphens)
      - guideline_version_id: UUID (hex + hyphens)
      - written_at: ISO 8601 timestamp

    This exact format must be reproduced identically for verification —
    documented in docs/runbooks/regulator_audit_response.md.

    Args:
        agent_outputs_hash: 64-char hex SHA-256 of agent outputs.
        decision_id: UUID string of the decision record.
        guideline_version_id: UUID string of the guideline version.
        written_at: ISO 8601 UTC timestamp string (e.g. "2026-06-01T12:00:00.000000+00:00").

    Returns:
        UTF-8 bytes of the pipe-separated message.
    """
    message = f"{agent_outputs_hash}|{decision_id}|{guideline_version_id}|{written_at}"
    return message.encode("utf-8")


def compute_record_hmac(
    agent_outputs_hash: str,
    decision_id: str,
    guideline_version_id: str,
    written_at: str,
) -> str:
    """
    Compute the HMAC-SHA256 signature for an audit record.

    This is the record_hmac field written to audit_records before the
    API responds. It binds the content hash to the decision metadata
    and proves the record was produced by this server (key holder).

    Args:
        agent_outputs_hash: SHA-256 hex of agent outputs.
        decision_id: UUID string.
        guideline_version_id: UUID string.
        written_at: ISO 8601 UTC timestamp as string.

    Returns:
        64-character lowercase hex HMAC-SHA256 digest.

    Raises:
        RuntimeError: If SERVER_HMAC_KEY is not configured.
    """
    key = _get_server_hmac_key()
    message = _build_hmac_message(
        agent_outputs_hash, decision_id, guideline_version_id, written_at
    )
    digest = hmac.new(key, message, digestmod=_HASH_ALGORITHM).hexdigest()
    return digest


def verify_record_hmac(
    stored_hmac: str,
    agent_outputs_hash: str,
    decision_id: str,
    guideline_version_id: str,
    written_at: str,
) -> bool:
    """
    Verify an audit record's HMAC against the stored value.

    Tries the current SERVER_HMAC_KEY first. If that fails AND
    SERVER_HMAC_KEY_PREVIOUS is set (rotation in progress), tries
    the previous key. This provides the 90-day overlap window.

    Uses hmac.compare_digest() for constant-time comparison to
    prevent timing attacks.

    Args:
        stored_hmac: The record_hmac value from audit_records.
        agent_outputs_hash: SHA-256 hex to reconstruct the message.
        decision_id: UUID string.
        guideline_version_id: UUID string.
        written_at: ISO 8601 UTC timestamp string.

    Returns:
        True if the HMAC is valid (either current or previous key).
        False if neither key produces a matching HMAC.

    Raises:
        RuntimeError: If SERVER_HMAC_KEY is not configured.
    """
    message = _build_hmac_message(
        agent_outputs_hash, decision_id, guideline_version_id, written_at
    )

    # Try current key
    current_key = _get_server_hmac_key()
    expected_current = hmac.new(current_key, message, digestmod=_HASH_ALGORITHM).hexdigest()
    if hmac.compare_digest(stored_hmac.lower(), expected_current.lower()):
        return True

    # Try previous key (during rotation window)
    previous_key = _get_previous_hmac_key()
    if previous_key is not None:
        expected_previous = hmac.new(previous_key, message, digestmod=_HASH_ALGORITHM).hexdigest()
        if hmac.compare_digest(stored_hmac.lower(), expected_previous.lower()):
            return True

    return False


def verify_sha256(data: bytes, expected_hash: str) -> bool:
    """
    Verify SHA-256 hash of data against an expected hex digest.

    Uses hmac.compare_digest() for constant-time comparison.

    Args:
        data: Bytes to hash.
        expected_hash: Expected 64-char hex digest.

    Returns:
        True if SHA-256(data) == expected_hash.
    """
    actual = compute_sha256(data)
    return hmac.compare_digest(actual.lower(), expected_hash.lower())