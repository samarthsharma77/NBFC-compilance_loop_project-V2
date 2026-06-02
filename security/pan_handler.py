"""
ComplianceLoop — PAN Handler
=============================
Handles all operations involving PAN (Permanent Account Number) cards.

DPDP & RBI KYC compliance rules enforced here:
  1. PAN plaintext NEVER leaves this module after hmac_pan() is called
  2. PAN is HMAC'd with PAN_HMAC_KEY — a key SEPARATE from SERVER_HMAC_KEY
     (separation means a compromise of one key doesn't affect both systems)
  3. The HMAC is stored in applications.pan_hmac — never the plaintext
  4. Format validation is done BEFORE hashing so invalid PANs are rejected
     at ingestion without storing anything
  5. Watchlists pre-hash their PAN entries with the same PAN_HMAC_KEY,
     enabling exact matching without ever exposing plaintext PANs in Redis

PAN format (Income Tax Department, India):
  [A-Z]{5}[0-9]{4}[A-Z]{1}
  - 5 alphabetic characters
  - 4 numeric digits
  - 1 alphabetic check character
  Example: ABCDE1234F

Why HMAC instead of SHA-256?
  SHA-256 of a PAN would be vulnerable to offline dictionary attacks because
  the PAN namespace is small (26^6 × 10^4 = ~309 billion possibilities,
  feasible with a GPU). HMAC-SHA256 with a 256-bit secret key makes
  dictionary attacks computationally infeasible without the key.

Key source: PAN_HMAC_KEY environment variable (or Vault)
"""

from __future__ import annotations

import hmac
import os
import re
from typing import Final

# ── PAN format ────────────────────────────────────────────────────────────────

# Official PAN regex per Income Tax Department specification
PAN_FORMAT_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$"
)

# The 4th character (index 3) encodes the taxpayer type:
# P=Person, C=Company, H=HUF, F=Firm, A=AOP, T=Trust, B=BOI, L=Local, J=AJP, G=Govt
PAN_TAXPAYER_TYPE_MAP: Final[dict[str, str]] = {
    "P": "Individual",
    "C": "Company",
    "H": "Hindu Undivided Family",
    "F": "Firm",
    "A": "Association of Persons",
    "T": "Trust",
    "B": "Body of Individuals",
    "L": "Local Authority",
    "J": "Artificial Juridical Person",
    "G": "Government",
}

_HASH_ALGORITHM: Final[str] = "sha256"


# ── Key loading ───────────────────────────────────────────────────────────────

_pan_hmac_key: bytes | None = None


def _load_pan_hmac_key() -> bytes:
    """
    Load PAN_HMAC_KEY from environment and validate it.

    Critically: verifies that PAN_HMAC_KEY != SERVER_HMAC_KEY.
    These MUST be different keys by design — if they were the same,
    a compromise of the PAN matching system would also compromise
    audit record integrity and vice versa.

    Raises:
        RuntimeError: If PAN_HMAC_KEY is missing, malformed, wrong length,
                      or identical to SERVER_HMAC_KEY.
    """
    raw = os.environ.get("PAN_HMAC_KEY", "")
    if not raw:
        raise RuntimeError(
            "PAN_HMAC_KEY environment variable is not set. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        key_bytes = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError(f"PAN_HMAC_KEY is not valid hex: {exc}") from exc

    if len(key_bytes) != 32:
        raise RuntimeError(
            f"PAN_HMAC_KEY must be exactly 32 bytes (64 hex chars). "
            f"Got {len(key_bytes)} bytes."
        )

    # Enforce key separation — PAN key must differ from server HMAC key
    server_key_raw = os.environ.get("SERVER_HMAC_KEY", "")
    if server_key_raw and raw == server_key_raw:
        raise RuntimeError(
            "SECURITY VIOLATION: PAN_HMAC_KEY and SERVER_HMAC_KEY must be different keys. "
            "Using the same key for both PAN hashing and audit signing reduces security. "
            "Generate a separate key for PAN_HMAC_KEY."
        )

    return key_bytes


def _get_pan_hmac_key() -> bytes:
    """Return cached PAN_HMAC_KEY, loading on first call."""
    global _pan_hmac_key  # noqa: PLW0603
    if _pan_hmac_key is None:
        _pan_hmac_key = _load_pan_hmac_key()
    return _pan_hmac_key


def invalidate_pan_key_cache() -> None:
    """Clear cached PAN key so it is reloaded on next use. Called after key rotation."""
    global _pan_hmac_key  # noqa: PLW0603
    _pan_hmac_key = None


# ── PAN validation ────────────────────────────────────────────────────────────

def validate_pan_format(pan: str) -> bool:
    """
    Validate PAN format against the Income Tax Department specification.

    Checks:
      1. Length is exactly 10 characters
      2. First 5 chars are uppercase letters
      3. Next 4 chars are digits
      4. Last char is an uppercase letter

    Args:
        pan: PAN string to validate. Will be uppercased before checking.

    Returns:
        True if format is valid, False otherwise.

    Note:
        This validates format only — not whether the PAN is actually
        registered with NSDL/UTIITSL. For that, the NBFC must use
        the ITD verification API (out of scope for this module).
    """
    if not pan or not isinstance(pan, str):
        return False
    return bool(PAN_FORMAT_REGEX.match(pan.upper().strip()))


def get_taxpayer_type(pan: str) -> str | None:
    """
    Extract taxpayer type from PAN's 4th character.

    Args:
        pan: Valid PAN string (will be uppercased).

    Returns:
        Human-readable taxpayer type string, or None if PAN is invalid.

    Example:
        get_taxpayer_type("ABCPE1234F") → "Individual"  (4th char = 'P')
    """
    pan_upper = pan.upper().strip()
    if not validate_pan_format(pan_upper):
        return None
    type_char = pan_upper[3]
    return PAN_TAXPAYER_TYPE_MAP.get(type_char, f"Unknown ({type_char})")


# ── PAN HMAC operations ───────────────────────────────────────────────────────

def hmac_pan(pan: str) -> str:
    """
    Compute HMAC-SHA256 of a PAN using PAN_HMAC_KEY.

    This is the ONLY function that accepts plaintext PAN as input.
    The plaintext PAN is not stored, logged, or returned — only the
    64-char hex HMAC digest is returned for storage.

    Call this function at ingestion time (API layer) and discard
    the plaintext PAN immediately after. The HMAC is what gets stored
    in applications.pan_hmac.

    Args:
        pan: Plaintext PAN string. Must pass validate_pan_format().
             Will be uppercased and stripped before hashing.

    Returns:
        64-character lowercase hex HMAC-SHA256 digest.

    Raises:
        ValueError: If PAN format is invalid.
        RuntimeError: If PAN_HMAC_KEY is not configured.

    Example:
        pan_hmac = hmac_pan("ABCDE1234F")
        # Store pan_hmac in DB, discard "ABCDE1234F"
    """
    pan_normalised = pan.upper().strip()
    if not validate_pan_format(pan_normalised):
        raise ValueError(
            f"Invalid PAN format. Expected [A-Z]{{5}}[0-9]{{4}}[A-Z]{{1}}. "
            f"Got a {len(pan)}-character string."
            # Deliberately not logging the PAN value itself
        )

    key = _get_pan_hmac_key()
    digest = hmac.new(
        key,
        pan_normalised.encode("utf-8"),
        digestmod=_HASH_ALGORITHM,
    ).hexdigest()
    return digest


def verify_pan_hmac(pan: str, stored_hmac: str) -> bool:
    """
    Verify that a plaintext PAN matches a stored HMAC.

    Used in situations where you have the PAN (e.g. from a re-submitted
    application) and need to verify it matches the stored HMAC without
    comparing plaintext PANs directly.

    Uses hmac.compare_digest() for constant-time comparison.

    Args:
        pan: Plaintext PAN to verify.
        stored_hmac: 64-char hex HMAC from applications.pan_hmac.

    Returns:
        True if HMAC(pan) == stored_hmac. False otherwise.

    Raises:
        ValueError: If PAN format is invalid.
        RuntimeError: If PAN_HMAC_KEY is not configured.
    """
    computed = hmac_pan(pan)
    return hmac.compare_digest(computed.lower(), stored_hmac.lower())


def hmac_pan_for_watchlist(pan: str) -> str:
    """
    Compute HMAC-SHA256 of a PAN for watchlist pre-processing.

    Functionally identical to hmac_pan() — same key, same algorithm.
    This is a separate function to make call sites explicit:
    you are hashing a PAN for watchlist storage, not for application storage.
    The output is the same as hmac_pan() — so watchlist lookup works by
    computing hmac_pan(applicant_pan) and checking if it exists in
    the pre-hashed watchlist.

    Args:
        pan: Plaintext PAN from a watchlist entry (e.g. OFAC SDN list).

    Returns:
        64-character lowercase hex HMAC-SHA256 digest.

    Raises:
        ValueError: If PAN format is invalid.
    """
    return hmac_pan(pan)


def mask_pan(pan: str) -> str:
    """
    Produce a masked version of a PAN safe for logging/display.

    Masks characters 3–8, preserving first 2 and last 2 characters.
    This is NOT for storage — only for display in UI or safe log output.

    Example:
        mask_pan("ABCDE1234F") → "AB*****34F"

    Args:
        pan: Plaintext PAN string.

    Returns:
        Masked string. Returns "INVALID" if format check fails.
    """
    pan_upper = pan.upper().strip()
    if not validate_pan_format(pan_upper):
        return "INVALID_PAN"
    # Show first 2 and last 2 characters, mask the middle 6
    return pan_upper[:2] + "*" * 6 + pan_upper[-2:]