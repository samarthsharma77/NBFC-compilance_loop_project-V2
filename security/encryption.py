"""
ComplianceLoop — AES-256-GCM Payload Encryption
================================================
Handles encryption and decryption of the `payload_encrypted` column
in the `applications` table. This column stores the full loan application
payload (including PII like date of birth, address, document content
references) in encrypted form at rest.

Algorithm: AES-256-GCM (Authenticated Encryption with Associated Data)
  - AES-256: 256-bit key, NIST-approved symmetric cipher
  - GCM mode: provides both confidentiality AND integrity/authenticity
  - 96-bit (12-byte) random nonce per encryption (GCM recommendation)
  - 128-bit (16-byte) authentication tag (GCM default)

Wire format (bytes stored in payload_encrypted):
  [version:1][nonce:12][tag:16][ciphertext:N]
  Total overhead: 29 bytes per record

  version=0x01 — allows future algorithm migration without schema change

Key source: AES_KEY env variable (32-byte hex string → 256-bit key)
           OR loaded from HashiCorp Vault if USE_VAULT=true

DPDP relevance:
  - Encrypting payload_encrypted means raw PII is never readable from
    a Postgres dump without the AES_KEY
  - The key is held in Vault / env, not in the database
  - On data retention wipe: payload_encrypted is set to NULL and the
    MinIO object is deleted — the encrypted bytes are gone, the key
    is irrelevant, and the audit hash/HMAC remain for non-repudiation
"""

from __future__ import annotations

import os
import secrets
import struct
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Constants ─────────────────────────────────────────────────────────────────

# Wire format version byte — increment when changing algorithm
_VERSION: Final[int] = 0x01
_VERSION_BYTE: Final[bytes] = struct.pack("B", _VERSION)

# Nonce size: 96 bits (12 bytes) — GCM recommended size
_NONCE_SIZE: Final[int] = 12

# Tag size: 128 bits (16 bytes) — AESGCM default
_TAG_SIZE: Final[int] = 16

# Minimum ciphertext length sanity check
_MIN_ENCRYPTED_LENGTH: Final[int] = 1 + _NONCE_SIZE + _TAG_SIZE + 1  # version + nonce + tag + 1 byte


# ── Key loading ───────────────────────────────────────────────────────────────

def _load_aes_key() -> bytes:
    """
    Load and validate the AES-256 key from environment.

    Expected format: 64-character hex string (32 bytes = 256 bits)
    Sourced from AES_KEY environment variable (or Vault — see secrets_loader).

    Raises:
        RuntimeError: If key is missing, wrong length, or not valid hex.
    """
    raw = os.environ.get("AES_KEY", "")
    if not raw:
        raise RuntimeError(
            "AES_KEY environment variable is not set. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        key_bytes = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError(
            f"AES_KEY is not valid hex: {exc}. "
            "Must be a 64-character hex string (32 bytes)."
        ) from exc

    if len(key_bytes) != 32:
        raise RuntimeError(
            f"AES_KEY must be exactly 32 bytes (256 bits). "
            f"Got {len(key_bytes)} bytes ({len(raw)} hex chars)."
        )
    return key_bytes


# Lazy singleton — loaded once, validated once
_aes_key: bytes | None = None


def _get_aes_key() -> bytes:
    """Return the cached AES key, loading it on first call."""
    global _aes_key  # noqa: PLW0603
    if _aes_key is None:
        _aes_key = _load_aes_key()
    return _aes_key


# ── Public API ────────────────────────────────────────────────────────────────

def encrypt_payload(plaintext: bytes) -> bytes:
    """
    Encrypt a payload using AES-256-GCM with a random nonce.

    Each call generates a fresh 12-byte cryptographically random nonce,
    so encrypting the same plaintext twice produces different ciphertext.
    This is the correct GCM usage — NEVER reuse a nonce with the same key.

    Args:
        plaintext: Raw bytes to encrypt. Typically JSON-serialised application
                   payload. Must not be empty.

    Returns:
        Encrypted bytes in wire format:
        [version:1][nonce:12][ciphertext+tag:N+16]
        The GCM authentication tag is appended to ciphertext by cryptography lib.

    Raises:
        ValueError: If plaintext is empty.
        RuntimeError: If AES_KEY is not configured.

    Example:
        encrypted = encrypt_payload(b'{"pan_hmac": "abc123..."}')
        # Store in applications.payload_encrypted
    """
    if not plaintext:
        raise ValueError("Cannot encrypt empty plaintext.")

    key = _get_aes_key()
    aesgcm = AESGCM(key)

    # Generate fresh random nonce — CRITICAL: never reuse nonce with same key
    nonce = secrets.token_bytes(_NONCE_SIZE)

    # AESGCM.encrypt returns ciphertext + authentication tag concatenated
    # No additional associated data (aad=None) — the HMAC in audit_records
    # provides the outer integrity check that binds encrypted payload to decision
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad=None)

    # Wire format: version || nonce || ciphertext_with_tag
    return _VERSION_BYTE + nonce + ciphertext_with_tag


def decrypt_payload(encrypted: bytes) -> bytes:
    """
    Decrypt a payload encrypted by encrypt_payload().

    Verifies the GCM authentication tag before returning plaintext —
    if the ciphertext has been tampered with, InvalidTag is raised
    and nothing is returned.

    Args:
        encrypted: Bytes in wire format produced by encrypt_payload().

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError: If encrypted bytes are malformed or too short.
        ValueError: If version byte is unsupported (future-proofing).
        cryptography.exceptions.InvalidTag: If authentication tag verification
            fails — indicates ciphertext tampering or wrong key.
        RuntimeError: If AES_KEY is not configured.

    Example:
        plaintext = decrypt_payload(row.payload_encrypted)
        payload = json.loads(plaintext)
    """
    if not encrypted:
        raise ValueError("Cannot decrypt empty ciphertext.")

    if len(encrypted) < _MIN_ENCRYPTED_LENGTH:
        raise ValueError(
            f"Encrypted payload too short: {len(encrypted)} bytes. "
            f"Minimum is {_MIN_ENCRYPTED_LENGTH} bytes."
        )

    # Parse wire format
    version = struct.unpack("B", encrypted[:1])[0]
    if version != _VERSION:
        raise ValueError(
            f"Unsupported encryption version: 0x{version:02x}. "
            f"Only version 0x{_VERSION:02x} is supported."
        )

    nonce = encrypted[1 : 1 + _NONCE_SIZE]
    ciphertext_with_tag = encrypted[1 + _NONCE_SIZE :]

    key = _get_aes_key()
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad=None)
    except InvalidTag as exc:
        # Do NOT include any payload content in this error message
        raise InvalidTag(
            "AES-GCM authentication tag verification failed. "
            "The payload may have been tampered with or the wrong key is being used."
        ) from exc

    return plaintext


def is_encrypted(data: bytes) -> bool:
    """
    Heuristic check: does this byte string look like a payload encrypted
    by encrypt_payload()?

    Checks the version byte and minimum length. Does NOT attempt decryption.
    Useful for migration checks and debugging.

    Args:
        data: Bytes to inspect.

    Returns:
        True if data matches expected wire format, False otherwise.
    """
    if len(data) < _MIN_ENCRYPTED_LENGTH:
        return False
    version = struct.unpack("B", data[:1])[0]
    return version == _VERSION


def rotate_encryption(
    old_encrypted: bytes,
    old_key_hex: str,
    new_key_hex: str | None = None,
) -> bytes:
    """
    Re-encrypt a payload under a new AES key.

    Used during key rotation (see scripts/rotate_secrets.sh).
    Decrypts with old_key_hex, re-encrypts with new_key_hex (or current AES_KEY).

    Args:
        old_encrypted: Payload encrypted under the old key.
        old_key_hex: 64-char hex string of the old AES key.
        new_key_hex: 64-char hex string of the new AES key.
                     If None, uses current AES_KEY from environment.

    Returns:
        Payload re-encrypted under the new key.

    Raises:
        ValueError: If either key is malformed.
        cryptography.exceptions.InvalidTag: If old key cannot decrypt the payload.
    """
    # Decrypt with old key
    try:
        old_key = bytes.fromhex(old_key_hex)
    except ValueError as exc:
        raise ValueError(f"old_key_hex is not valid hex: {exc}") from exc

    if len(old_key) != 32:
        raise ValueError(f"old_key_hex must be 32 bytes. Got {len(old_key)}.")

    # Temporarily swap the module-level key for decryption
    version = struct.unpack("B", old_encrypted[:1])[0]
    if version != _VERSION:
        raise ValueError(f"Unsupported version: 0x{version:02x}")

    nonce = old_encrypted[1 : 1 + _NONCE_SIZE]
    ciphertext_with_tag = old_encrypted[1 + _NONCE_SIZE :]

    old_aesgcm = AESGCM(old_key)
    plaintext = old_aesgcm.decrypt(nonce, ciphertext_with_tag, aad=None)

    # Re-encrypt with new key
    if new_key_hex is not None:
        try:
            new_key = bytes.fromhex(new_key_hex)
        except ValueError as exc:
            raise ValueError(f"new_key_hex is not valid hex: {exc}") from exc
        if len(new_key) != 32:
            raise ValueError(f"new_key_hex must be 32 bytes. Got {len(new_key)}.")
        new_aesgcm = AESGCM(new_key)
        new_nonce = secrets.token_bytes(_NONCE_SIZE)
        new_ciphertext = new_aesgcm.encrypt(new_nonce, plaintext, aad=None)
        return _VERSION_BYTE + new_nonce + new_ciphertext

    # Use current environment key
    return encrypt_payload(plaintext)