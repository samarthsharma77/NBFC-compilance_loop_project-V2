"""
Tests for security/encryption.py

Covers:
  - encrypt_payload / decrypt_payload round-trip
  - Wire format structure (version byte, nonce, tag)
  - Nonce uniqueness (two encryptions of same plaintext produce different ciphertext)
  - Tamper detection (GCM authentication tag catches modification)
  - Error handling (empty input, wrong version, truncated data)
  - rotate_encryption (re-encryption under new key)
  - is_encrypted heuristic
"""

from __future__ import annotations

import json
import os
import secrets
import struct

import pytest
from cryptography.exceptions import InvalidTag

# ── Test fixtures — set required env vars before importing module ─────────────

TEST_AES_KEY = secrets.token_hex(32)          # 64-char hex = 32 bytes = 256 bits
DIFFERENT_AES_KEY = secrets.token_hex(32)     # Different key for rotation tests


@pytest.fixture(autouse=True)
def set_aes_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set AES_KEY env var and reset module key cache before each test."""
    monkeypatch.setenv("AES_KEY", TEST_AES_KEY)
    # Reset the cached key so each test gets a fresh load
    import security.encryption as enc  # noqa: PLC0415
    enc._aes_key = None  # noqa: SLF001


# ── Import under test ─────────────────────────────────────────────────────────

from security.encryption import (  # noqa: E402
    _NONCE_SIZE,
    _TAG_SIZE,
    _VERSION,
    decrypt_payload,
    encrypt_payload,
    is_encrypted,
    rotate_encryption,
)


# ── Round-trip tests ──────────────────────────────────────────────────────────

class TestEncryptDecryptRoundTrip:

    def test_basic_roundtrip(self) -> None:
        """Encrypt and decrypt returns original plaintext."""
        plaintext = b"Hello, ComplianceLoop!"
        encrypted = encrypt_payload(plaintext)
        assert decrypt_payload(encrypted) == plaintext

    def test_json_payload_roundtrip(self) -> None:
        """Realistic application payload survives round-trip."""
        payload = {
            "application_id": "550e8400-e29b-41d4-a716-446655440000",
            "applicant_name": "Rahul Sharma",
            "pan_hmac": "a" * 64,
            "declared_income": 75000.00,
            "loan_amount_requested": 500000.00,
            "loan_purpose": "PERSONAL_UNSECURED",
        }
        plaintext = json.dumps(payload).encode("utf-8")
        encrypted = encrypt_payload(plaintext)
        decrypted = decrypt_payload(encrypted)
        assert json.loads(decrypted) == payload

    def test_empty_bytes_raises(self) -> None:
        """Encrypting empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="Cannot encrypt empty plaintext"):
            encrypt_payload(b"")

    def test_decrypt_empty_raises(self) -> None:
        """Decrypting empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="Cannot decrypt empty ciphertext"):
            decrypt_payload(b"")

    def test_large_payload_roundtrip(self) -> None:
        """Large payload (1MB) survives round-trip."""
        plaintext = secrets.token_bytes(1024 * 1024)
        encrypted = encrypt_payload(plaintext)
        assert decrypt_payload(encrypted) == plaintext

    def test_binary_payload_roundtrip(self) -> None:
        """Binary data (not just UTF-8 text) survives round-trip."""
        plaintext = bytes(range(256)) * 100
        encrypted = encrypt_payload(plaintext)
        assert decrypt_payload(encrypted) == plaintext

    def test_single_byte_roundtrip(self) -> None:
        """Single byte payload works."""
        plaintext = b"\xff"
        encrypted = encrypt_payload(plaintext)
        assert decrypt_payload(encrypted) == plaintext


# ── Wire format tests ─────────────────────────────────────────────────────────

class TestWireFormat:

    def test_version_byte(self) -> None:
        """First byte of encrypted output is the version byte."""
        encrypted = encrypt_payload(b"test")
        version = struct.unpack("B", encrypted[:1])[0]
        assert version == _VERSION

    def test_minimum_length(self) -> None:
        """Encrypted output has minimum expected length: 1 + 12 + 16 + 1 = 30 bytes."""
        encrypted = encrypt_payload(b"x")
        min_len = 1 + _NONCE_SIZE + _TAG_SIZE + 1
        assert len(encrypted) >= min_len

    def test_overhead_size(self) -> None:
        """Encrypted output is plaintext + 29 bytes overhead (version + nonce + tag)."""
        plaintext = b"hello world"
        encrypted = encrypt_payload(plaintext)
        overhead = 1 + _NONCE_SIZE + _TAG_SIZE
        assert len(encrypted) == len(plaintext) + overhead

    def test_nonce_is_unique_per_call(self) -> None:
        """
        Two encryptions of same plaintext produce different nonces
        and different ciphertext — proves nonce is random per call.
        """
        plaintext = b"same data"
        enc1 = encrypt_payload(plaintext)
        enc2 = encrypt_payload(plaintext)
        # Extract nonces
        nonce1 = enc1[1 : 1 + _NONCE_SIZE]
        nonce2 = enc2[1 : 1 + _NONCE_SIZE]
        assert nonce1 != nonce2
        # Full ciphertext must also differ
        assert enc1 != enc2

    def test_nonce_uniqueness_across_many_calls(self) -> None:
        """1000 encryptions produce 1000 unique nonces — no collision."""
        nonces: set[bytes] = set()
        for _ in range(1000):
            encrypted = encrypt_payload(b"payload")
            nonce = encrypted[1 : 1 + _NONCE_SIZE]
            nonces.add(nonce)
        assert len(nonces) == 1000, "Nonce collision detected — CRITICAL security issue"


# ── Tamper detection tests ────────────────────────────────────────────────────

class TestTamperDetection:

    def test_tamper_ciphertext_raises_invalid_tag(self) -> None:
        """Modifying any ciphertext byte causes GCM tag verification to fail."""
        encrypted = encrypt_payload(b"important compliance data")
        tampered = bytearray(encrypted)
        # Flip a bit in the ciphertext (after version + nonce + tag)
        tampered[1 + _NONCE_SIZE + _TAG_SIZE] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_payload(bytes(tampered))

    def test_tamper_tag_raises_invalid_tag(self) -> None:
        """Modifying the authentication tag raises InvalidTag."""
        encrypted = encrypt_payload(b"data")
        tampered = bytearray(encrypted)
        tag_start = 1 + _NONCE_SIZE
        tampered[tag_start] ^= 0x01
        with pytest.raises(InvalidTag):
            decrypt_payload(bytes(tampered))

    def test_tamper_nonce_raises_invalid_tag(self) -> None:
        """Modifying the nonce causes decryption to produce garbage that fails tag check."""
        encrypted = encrypt_payload(b"data")
        tampered = bytearray(encrypted)
        tampered[1] ^= 0xFF  # Flip bits in first nonce byte
        with pytest.raises((InvalidTag, Exception)):
            decrypt_payload(bytes(tampered))

    def test_wrong_key_raises_invalid_tag(self) -> None:
        """Decrypting with wrong key raises InvalidTag."""
        encrypted = encrypt_payload(b"data")
        # Temporarily change the key
        import security.encryption as enc  # noqa: PLC0415
        enc._aes_key = secrets.token_bytes(32)  # noqa: SLF001
        with pytest.raises(InvalidTag):
            decrypt_payload(encrypted)

    def test_truncated_ciphertext_raises(self) -> None:
        """Truncated ciphertext is rejected before decryption attempt."""
        encrypted = encrypt_payload(b"data")
        truncated = encrypted[:10]  # Way too short
        with pytest.raises(ValueError, match="too short"):
            decrypt_payload(truncated)

    def test_wrong_version_byte_raises(self) -> None:
        """Unknown version byte raises ValueError."""
        encrypted = encrypt_payload(b"data")
        corrupted = b"\x99" + encrypted[1:]  # version 0x99 doesn't exist
        with pytest.raises(ValueError, match="Unsupported encryption version"):
            decrypt_payload(corrupted)


# ── Key configuration tests ───────────────────────────────────────────────────

class TestKeyConfiguration:

    def test_missing_aes_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing AES_KEY env var raises RuntimeError."""
        monkeypatch.delenv("AES_KEY", raising=False)
        import security.encryption as enc  # noqa: PLC0415
        enc._aes_key = None  # noqa: SLF001
        with pytest.raises(RuntimeError, match="AES_KEY environment variable is not set"):
            encrypt_payload(b"test")

    def test_short_aes_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AES_KEY shorter than 32 bytes raises RuntimeError."""
        monkeypatch.setenv("AES_KEY", secrets.token_hex(16))  # 16 bytes — too short
        import security.encryption as enc  # noqa: PLC0415
        enc._aes_key = None  # noqa: SLF001
        with pytest.raises(RuntimeError, match="must be exactly 32 bytes"):
            encrypt_payload(b"test")

    def test_non_hex_aes_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-hex AES_KEY raises RuntimeError."""
        monkeypatch.setenv("AES_KEY", "not-valid-hex-string-but-64-chars-" + "x" * 30)
        import security.encryption as enc  # noqa: PLC0415
        enc._aes_key = None  # noqa: SLF001
        with pytest.raises(RuntimeError, match="not valid hex"):
            encrypt_payload(b"test")


# ── is_encrypted tests ────────────────────────────────────────────────────────

class TestIsEncrypted:

    def test_encrypted_bytes_returns_true(self) -> None:
        encrypted = encrypt_payload(b"test data")
        assert is_encrypted(encrypted) is True

    def test_plaintext_returns_false(self) -> None:
        assert is_encrypted(b"plaintext JSON data here") is False

    def test_empty_returns_false(self) -> None:
        assert is_encrypted(b"") is False

    def test_too_short_returns_false(self) -> None:
        assert is_encrypted(b"\x01\x02\x03") is False

    def test_wrong_version_byte_returns_false(self) -> None:
        encrypted = encrypt_payload(b"data")
        wrong_version = b"\x99" + encrypted[1:]
        assert is_encrypted(wrong_version) is False


# ── rotate_encryption tests ───────────────────────────────────────────────────

class TestRotateEncryption:

    def test_rotate_to_new_key(self) -> None:
        """rotate_encryption re-encrypts under new key and produces same plaintext."""
        plaintext = b"sensitive application payload"
        old_encrypted = encrypt_payload(plaintext)

        # Rotate to different key
        new_encrypted = rotate_encryption(
            old_encrypted=old_encrypted,
            old_key_hex=TEST_AES_KEY,
            new_key_hex=DIFFERENT_AES_KEY,
        )

        # Old encrypted and new encrypted should differ (different nonce + key)
        assert old_encrypted != new_encrypted

        # Decrypt with new key
        import security.encryption as enc  # noqa: PLC0415
        enc._aes_key = bytes.fromhex(DIFFERENT_AES_KEY)  # noqa: SLF001
        result = decrypt_payload(new_encrypted)
        assert result == plaintext

    def test_rotate_wrong_old_key_raises(self) -> None:
        """rotate_encryption with wrong old key raises InvalidTag."""
        plaintext = b"payload"
        encrypted = encrypt_payload(plaintext)
        wrong_key = secrets.token_hex(32)
        with pytest.raises(InvalidTag):
            rotate_encryption(
                old_encrypted=encrypted,
                old_key_hex=wrong_key,
                new_key_hex=DIFFERENT_AES_KEY,
            )

    def test_rotate_invalid_old_key_hex_raises(self) -> None:
        """rotate_encryption with non-hex old key raises ValueError."""
        encrypted = encrypt_payload(b"payload")
        with pytest.raises(ValueError, match="not valid hex"):
            rotate_encryption(
                old_encrypted=encrypted,
                old_key_hex="not-hex",
                new_key_hex=DIFFERENT_AES_KEY,
            )