"""
Tests for security/pan_handler.py

Covers:
  - PAN format validation (valid/invalid formats)
  - PAN HMAC computation and verification
  - Key separation enforcement (PAN_HMAC_KEY != SERVER_HMAC_KEY)
  - Watchlist HMAC matching (same key = same digest = lookup works)
  - Masking for safe display/logging
  - Taxpayer type extraction
  - Error handling (missing key, invalid format, empty input)
  - Constant-time comparison (verify_pan_hmac)
"""

from __future__ import annotations

import hmac
import os
import secrets

import pytest

# ── Test key setup ─────────────────────────────────────────────────────────────

TEST_PAN_HMAC_KEY = secrets.token_hex(32)
TEST_SERVER_HMAC_KEY = secrets.token_hex(32)   # Must differ from PAN key

# Ensure they are actually different (astronomically unlikely to collide but check)
while TEST_SERVER_HMAC_KEY == TEST_PAN_HMAC_KEY:
    TEST_SERVER_HMAC_KEY = secrets.token_hex(32)

# Valid PAN samples covering all taxpayer types
VALID_PANS = [
    "ABCDE1234F",   # Generic valid
    "AABCP1234C",   # Individual (P at position 4)
    "AAAAC1234C",   # Company (C at position 4)
    "AAABH1234H",   # HUF
    "AAABF1234F",   # Firm
    "ZZZZT9999Z",   # Edge case — all Zs and 9s
    "AAAAA0000A",   # Edge case — all As and 0s
]

INVALID_PANS = [
    "",                  # Empty
    "ABCDE123",          # Too short (9 chars)
    "ABCDE12345",        # Too long (10 chars but wrong — digit at end)
    "abcde1234f",        # Lowercase — though we uppercase internally
    "ABCDE123456",       # 11 chars
    "1BCDE1234F",        # Starts with digit
    "ABCDE1234 ",        # Trailing space (after strip this becomes valid — test strips)
    "ABCDE-234F",        # Hyphen in numeric section
    "ABCD11234F",        # 4 chars then digit (5th should be alpha)
    None,                # None type  # type: ignore[list-item]
    123,                 # Integer   # type: ignore[list-item]
]


@pytest.fixture(autouse=True)
def set_pan_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set required env vars and reset key cache before each test."""
    monkeypatch.setenv("PAN_HMAC_KEY", TEST_PAN_HMAC_KEY)
    monkeypatch.setenv("SERVER_HMAC_KEY", TEST_SERVER_HMAC_KEY)
    # Reset module-level key cache
    import security.pan_handler as ph  # noqa: PLC0415
    ph._pan_hmac_key = None  # noqa: SLF001


from security.pan_handler import (  # noqa: E402
    PAN_FORMAT_REGEX,
    get_taxpayer_type,
    hmac_pan,
    hmac_pan_for_watchlist,
    mask_pan,
    validate_pan_format,
    verify_pan_hmac,
)


# ── validate_pan_format tests ─────────────────────────────────────────────────

class TestValidatePanFormat:

    @pytest.mark.parametrize("pan", VALID_PANS)
    def test_valid_pans_return_true(self, pan: str) -> None:
        assert validate_pan_format(pan) is True

    def test_lowercase_is_valid_after_normalisation(self) -> None:
        """validate_pan_format uppercases before checking."""
        assert validate_pan_format("abcde1234f") is True

    def test_valid_pan_with_surrounding_whitespace(self) -> None:
        """Leading/trailing spaces are stripped before validation."""
        assert validate_pan_format("  ABCDE1234F  ") is True

    def test_empty_string_is_invalid(self) -> None:
        assert validate_pan_format("") is False

    def test_none_is_invalid(self) -> None:
        assert validate_pan_format(None) is False  # type: ignore[arg-type]

    def test_integer_is_invalid(self) -> None:
        assert validate_pan_format(123) is False  # type: ignore[arg-type]

    def test_too_short_is_invalid(self) -> None:
        assert validate_pan_format("ABCDE123") is False   # 9 chars

    def test_too_long_is_invalid(self) -> None:
        assert validate_pan_format("ABCDE12345F") is False  # 11 chars

    def test_digit_in_first_5_is_invalid(self) -> None:
        assert validate_pan_format("ABC1E1234F") is False

    def test_letter_in_middle_4_is_invalid(self) -> None:
        assert validate_pan_format("ABCDEA234F") is False

    def test_digit_as_last_char_is_invalid(self) -> None:
        assert validate_pan_format("ABCDE12341") is False

    def test_special_char_is_invalid(self) -> None:
        assert validate_pan_format("ABCDE123@F") is False

    def test_pan_format_regex_is_exported(self) -> None:
        """PAN_FORMAT_REGEX is accessible as a module-level constant."""
        assert PAN_FORMAT_REGEX is not None
        assert PAN_FORMAT_REGEX.match("ABCDE1234F") is not None
        assert PAN_FORMAT_REGEX.match("invalid") is None


# ── hmac_pan tests ─────────────────────────────────────────────────────────────

class TestHmacPan:

    def test_returns_64_char_hex_string(self) -> None:
        """HMAC-SHA256 output is 64 hex characters."""
        result = hmac_pan("ABCDE1234F")
        assert isinstance(result, str)
        assert len(result) == 64
        # Must be valid hex
        int(result, 16)

    def test_deterministic(self) -> None:
        """Same PAN + same key always produces same HMAC."""
        result1 = hmac_pan("ABCDE1234F")
        result2 = hmac_pan("ABCDE1234F")
        assert result1 == result2

    def test_different_pans_produce_different_hmacs(self) -> None:
        """Different PANs produce different HMACs."""
        h1 = hmac_pan("ABCDE1234F")
        h2 = hmac_pan("ABCDE1234G")  # Only last char differs
        assert h1 != h2

    def test_lowercase_pan_same_as_uppercase(self) -> None:
        """PAN is normalised to uppercase before hashing."""
        h_upper = hmac_pan("ABCDE1234F")
        h_lower = hmac_pan("abcde1234f")
        assert h_upper == h_lower

    def test_pan_with_spaces_same_as_stripped(self) -> None:
        """Leading/trailing spaces are stripped before hashing."""
        h_clean = hmac_pan("ABCDE1234F")
        h_spaced = hmac_pan("  ABCDE1234F  ")
        assert h_clean == h_spaced

    def test_invalid_pan_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid PAN format"):
            hmac_pan("NOTAPAN")

    def test_empty_pan_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid PAN format"):
            hmac_pan("")

    def test_plaintext_pan_not_in_output(self) -> None:
        """The plaintext PAN must not appear anywhere in the returned string."""
        pan = "ABCDE1234F"
        result = hmac_pan(pan)
        assert pan not in result
        assert pan.lower() not in result

    def test_different_key_produces_different_hmac(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Changing PAN_HMAC_KEY produces a different HMAC for the same PAN."""
        h1 = hmac_pan("ABCDE1234F")

        # Change key
        monkeypatch.setenv("PAN_HMAC_KEY", secrets.token_hex(32))
        import security.pan_handler as ph  # noqa: PLC0415
        ph._pan_hmac_key = None  # noqa: SLF001

        h2 = hmac_pan("ABCDE1234F")
        assert h1 != h2

    def test_missing_pan_hmac_key_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing PAN_HMAC_KEY raises RuntimeError."""
        monkeypatch.delenv("PAN_HMAC_KEY", raising=False)
        import security.pan_handler as ph  # noqa: PLC0415
        ph._pan_hmac_key = None  # noqa: SLF001
        with pytest.raises(RuntimeError, match="PAN_HMAC_KEY environment variable is not set"):
            hmac_pan("ABCDE1234F")

    def test_short_pan_hmac_key_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PAN_HMAC_KEY shorter than 32 bytes raises RuntimeError."""
        monkeypatch.setenv("PAN_HMAC_KEY", secrets.token_hex(16))  # 16 bytes
        import security.pan_handler as ph  # noqa: PLC0415
        ph._pan_hmac_key = None  # noqa: SLF001
        with pytest.raises(RuntimeError, match="must be exactly 32 bytes"):
            hmac_pan("ABCDE1234F")


# ── Key separation tests ───────────────────────────────────────────────────────

class TestKeySeparation:

    def test_pan_key_same_as_server_key_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        SECURITY: If PAN_HMAC_KEY == SERVER_HMAC_KEY, loading must fail.
        This enforces key separation between audit signing and PAN hashing.
        """
        same_key = secrets.token_hex(32)
        monkeypatch.setenv("PAN_HMAC_KEY", same_key)
        monkeypatch.setenv("SERVER_HMAC_KEY", same_key)
        import security.pan_handler as ph  # noqa: PLC0415
        ph._pan_hmac_key = None  # noqa: SLF001
        with pytest.raises(RuntimeError, match="SECURITY VIOLATION"):
            hmac_pan("ABCDE1234F")

    def test_pan_hmac_differs_from_server_hmac_for_same_input(self) -> None:
        """
        PAN HMAC and server HMAC of the same data produce different outputs
        because they use different keys.
        """
        from security.hmac_utils import compute_record_hmac  # noqa: PLC0415

        # Set SERVER_HMAC_KEY to known value (different from PAN key)
        import security.hmac_utils as hu  # noqa: PLC0415
        import os  # noqa: PLC0415, PLW0611
        hu._server_hmac_key = bytes.fromhex(TEST_SERVER_HMAC_KEY)  # noqa: SLF001

        pan = "ABCDE1234F"
        pan_digest = hmac_pan(pan)

        # Compute server HMAC of the same PAN string (as if it were a message)
        # This would never happen in production but proves key separation
        server_digest = hmac.new(
            bytes.fromhex(TEST_SERVER_HMAC_KEY),
            pan.encode(),
            digestmod="sha256",
        ).hexdigest()

        assert pan_digest != server_digest


# ── verify_pan_hmac tests ─────────────────────────────────────────────────────

class TestVerifyPanHmac:

    def test_correct_pan_returns_true(self) -> None:
        pan = "ABCDE1234F"
        stored_hmac = hmac_pan(pan)
        assert verify_pan_hmac(pan, stored_hmac) is True

    def test_wrong_pan_returns_false(self) -> None:
        stored_hmac = hmac_pan("ABCDE1234F")
        assert verify_pan_hmac("ABCDE1234G", stored_hmac) is False

    def test_tampered_hmac_returns_false(self) -> None:
        pan = "ABCDE1234F"
        stored_hmac = hmac_pan(pan)
        # Flip last character
        tampered = stored_hmac[:-1] + ("a" if stored_hmac[-1] != "a" else "b")
        assert verify_pan_hmac(pan, tampered) is False

    def test_invalid_pan_in_verify_raises(self) -> None:
        """verify_pan_hmac with invalid PAN format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid PAN format"):
            verify_pan_hmac("NOTAPAN", "a" * 64)

    def test_verification_is_case_insensitive_for_stored_hmac(self) -> None:
        """Stored HMAC comparison is case-insensitive (both are hex)."""
        pan = "ABCDE1234F"
        stored_hmac = hmac_pan(pan).upper()  # Uppercase the stored HMAC
        assert verify_pan_hmac(pan, stored_hmac) is True

    def test_constant_time_comparison(self) -> None:
        """
        Verify that comparison uses hmac.compare_digest (constant-time).
        We can't directly test timing, but we can verify wrong HMACs all
        return False without raising exceptions, as expected from constant-time code.
        """
        pan = "ABCDE1234F"
        correct_hmac = hmac_pan(pan)
        # All of these should return False without exceptions
        assert verify_pan_hmac(pan, "0" * 64) is False
        assert verify_pan_hmac(pan, "f" * 64) is False
        assert verify_pan_hmac(pan, correct_hmac[:-1] + "0") is False


# ── hmac_pan_for_watchlist tests ──────────────────────────────────────────────

class TestHmacPanForWatchlist:

    def test_watchlist_hmac_matches_application_hmac(self) -> None:
        """
        CRITICAL: Watchlist HMAC must match application HMAC for the same PAN.
        This is what enables sanctions lookup: compute hmac_pan(applicant_pan)
        and check if it exists in the pre-hashed watchlist.
        """
        pan = "ABCDE1234F"
        application_hmac = hmac_pan(pan)
        watchlist_hmac = hmac_pan_for_watchlist(pan)
        assert application_hmac == watchlist_hmac

    def test_watchlist_hmac_different_pans_do_not_collide(self) -> None:
        """Different PANs produce different watchlist HMACs (no false positives)."""
        pans = ["ABCDE1234F", "ABCDE1234G", "XYZPQ9876K", "AAAAA0000A"]
        hmacs = [hmac_pan_for_watchlist(p) for p in pans]
        assert len(set(hmacs)) == len(pans), "Watchlist HMAC collision detected"

    def test_watchlist_function_validates_pan_format(self) -> None:
        """hmac_pan_for_watchlist also validates PAN format."""
        with pytest.raises(ValueError, match="Invalid PAN format"):
            hmac_pan_for_watchlist("INVALID")


# ── mask_pan tests ─────────────────────────────────────────────────────────────

class TestMaskPan:

    def test_valid_pan_is_masked(self) -> None:
        masked = mask_pan("ABCDE1234F")
        assert masked == "AB******4F"

    def test_masked_pan_does_not_contain_middle_chars(self) -> None:
        pan = "ABCDE1234F"
        masked = mask_pan(pan)
        # Middle 6 characters should not appear
        assert "CDE123" not in masked

    def test_masked_length_is_10(self) -> None:
        """Masked PAN is always 10 characters (same as original)."""
        masked = mask_pan("ABCDE1234F")
        assert len(masked) == 10

    def test_masked_shows_first_2_chars(self) -> None:
        masked = mask_pan("XYZPQ1234A")
        assert masked.startswith("XY")

    def test_masked_shows_last_2_chars(self) -> None:
        masked = mask_pan("XYZPQ1234A")
        assert masked.endswith("4A")

    def test_masked_middle_is_asterisks(self) -> None:
        masked = mask_pan("ABCDE1234F")
        assert masked[2:8] == "******"

    def test_lowercase_pan_is_masked_as_uppercase(self) -> None:
        masked = mask_pan("abcde1234f")
        assert masked == "AB******4F"

    def test_invalid_pan_returns_invalid_string(self) -> None:
        masked = mask_pan("NOTAPAN")
        assert masked == "INVALID_PAN"

    def test_empty_returns_invalid_string(self) -> None:
        masked = mask_pan("")
        assert masked == "INVALID_PAN"

    def test_mask_is_safe_for_logging(self) -> None:
        """
        Masked PAN should not reveal enough information to reconstruct the PAN.
        Only first 2 and last 2 chars are visible.
        """
        pan = "ABCDE1234F"
        masked = mask_pan(pan)
        # Count non-asterisk chars — should be 4 (first 2 + last 2)
        non_masked = [c for c in masked if c != "*"]
        assert len(non_masked) == 4


# ── get_taxpayer_type tests ───────────────────────────────────────────────────

class TestGetTaxpayerType:

    def test_individual(self) -> None:
        # 4th char (index 3) = P → Individual
        assert get_taxpayer_type("AABCP1234A") == "Individual"

    def test_company(self) -> None:
        assert get_taxpayer_type("AAAAC1234A") == "Company"

    def test_huf(self) -> None:
        assert get_taxpayer_type("AAABH1234A") == "Hindu Undivided Family"

    def test_firm(self) -> None:
        assert get_taxpayer_type("AAABF1234A") == "Firm"

    def test_trust(self) -> None:
        assert get_taxpayer_type("AAABT1234A") == "Trust"

    def test_invalid_pan_returns_none(self) -> None:
        assert get_taxpayer_type("INVALID") is None

    def test_unknown_type_char_returns_unknown_string(self) -> None:
        # Create a PAN with a valid format but unknown type char (e.g. 'X')
        # X is not in the taxpayer type map
        result = get_taxpayer_type("AAABX1234A")
        assert result is not None
        assert "Unknown" in result

    def test_lowercase_input_works(self) -> None:
        """get_taxpayer_type normalises to uppercase internally."""
        assert get_taxpayer_type("aabcp1234a") == "Individual"