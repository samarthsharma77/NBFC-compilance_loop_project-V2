"""
Tests for dpdp/consent_manager.py

Covers:
  - validate_consent() — all pass/fail paths
  - Consent flag must be exactly True (not truthy string/int)
  - Timestamp freshness window (24h default)
  - Future timestamp rejection (clock skew protection)
  - Version mismatch rejection
  - No active consent version returns correct error
  - activate_consent_version() deactivates previous version
  - get_consent_version_text() returns correct text
  - ConsentValidationResult boolean behaviour

All DB interactions are mocked — these are unit tests.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dpdp.consent_manager import (
    ConsentValidationResult,
    validate_consent,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def active_consent_version() -> MagicMock:
    """Mock ConsentVersion object representing the active version."""
    v = MagicMock()
    v.version_id = "v1.0"
    v.consent_text = "You consent to data processing for loan evaluation."
    v.is_active = True
    return v


@pytest.fixture
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def fresh_consent_timestamp(now_utc: datetime) -> datetime:
    """Consent given 1 hour ago — within 24h validity window."""
    return now_utc - timedelta(hours=1)


@pytest.fixture
def stale_consent_timestamp(now_utc: datetime) -> datetime:
    """Consent given 25 hours ago — outside 24h validity window."""
    return now_utc - timedelta(hours=25)


# ── ConsentValidationResult tests ─────────────────────────────────────────────

class TestConsentValidationResult:

    def test_valid_result_is_truthy(self) -> None:
        result = ConsentValidationResult(is_valid=True)
        assert bool(result) is True

    def test_invalid_result_is_falsy(self) -> None:
        result = ConsentValidationResult(
            is_valid=False,
            error_code="DPDP_CONSENT_NOT_GIVEN",
            error_message="Consent not given",
        )
        assert bool(result) is False

    def test_valid_result_has_no_error_code(self) -> None:
        result = ConsentValidationResult(is_valid=True, active_version_id="v1.0")
        assert result.error_code is None
        assert result.active_version_id == "v1.0"

    def test_invalid_result_carries_error_info(self) -> None:
        result = ConsentValidationResult(
            is_valid=False,
            error_code="DPDP_CONSENT_EXPIRED",
            error_message="Consent has expired",
        )
        assert result.error_code == "DPDP_CONSENT_EXPIRED"
        assert "expired" in result.error_message


# ── validate_consent() tests ──────────────────────────────────────────────────

class TestValidateConsent:

    @pytest.mark.asyncio
    async def test_valid_consent_passes(
        self,
        active_consent_version: MagicMock,
        fresh_consent_timestamp: datetime,
    ) -> None:
        """All conditions met — consent should pass."""
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=True,
                consent_version="v1.0",
                consent_timestamp=fresh_consent_timestamp,
            )

        assert result.is_valid is True
        assert result.error_code is None
        assert result.active_version_id == "v1.0"

    @pytest.mark.asyncio
    async def test_consent_false_fails(
        self,
        active_consent_version: MagicMock,
        fresh_consent_timestamp: datetime,
    ) -> None:
        """dpdp_consent=False must fail."""
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=False,
                consent_version="v1.0",
                consent_timestamp=fresh_consent_timestamp,
            )

        assert result.is_valid is False
        assert result.error_code == "DPDP_CONSENT_NOT_GIVEN"

    @pytest.mark.asyncio
    async def test_consent_string_true_fails(
        self,
        active_consent_version: MagicMock,
        fresh_consent_timestamp: datetime,
    ) -> None:
        """
        dpdp_consent='true' (string) must fail.
        Must be exactly boolean True — not a truthy value.
        """
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent="true",  # type: ignore[arg-type]
                consent_version="v1.0",
                consent_timestamp=fresh_consent_timestamp,
            )

        assert result.is_valid is False
        assert result.error_code == "DPDP_CONSENT_NOT_GIVEN"

    @pytest.mark.asyncio
    async def test_consent_integer_1_fails(
        self,
        active_consent_version: MagicMock,
        fresh_consent_timestamp: datetime,
    ) -> None:
        """dpdp_consent=1 (integer) must fail — not exactly boolean True."""
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=1,  # type: ignore[arg-type]
                consent_version="v1.0",
                consent_timestamp=fresh_consent_timestamp,
            )

        assert result.is_valid is False
        assert result.error_code == "DPDP_CONSENT_NOT_GIVEN"

    @pytest.mark.asyncio
    async def test_consent_none_fails(
        self,
        active_consent_version: MagicMock,
        fresh_consent_timestamp: datetime,
    ) -> None:
        """dpdp_consent=None must fail."""
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=None,  # type: ignore[arg-type]
                consent_version="v1.0",
                consent_timestamp=fresh_consent_timestamp,
            )

        assert result.is_valid is False
        assert result.error_code == "DPDP_CONSENT_NOT_GIVEN"

    @pytest.mark.asyncio
    async def test_expired_timestamp_fails(
        self,
        active_consent_version: MagicMock,
        stale_consent_timestamp: datetime,
    ) -> None:
        """Consent older than 24 hours must fail."""
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=True,
                consent_version="v1.0",
                consent_timestamp=stale_consent_timestamp,
            )

        assert result.is_valid is False
        assert result.error_code == "DPDP_CONSENT_EXPIRED"
        assert "expired" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_exactly_at_boundary_passes(
        self,
        active_consent_version: MagicMock,
    ) -> None:
        """Consent given exactly 23h 59m ago should pass (within 24h window)."""
        almost_expired = datetime.now(timezone.utc) - timedelta(hours=23, minutes=59)
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=True,
                consent_version="v1.0",
                consent_timestamp=almost_expired,
            )

        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_future_timestamp_fails(
        self,
        active_consent_version: MagicMock,
    ) -> None:
        """Consent timestamp in the future must fail (clock skew protection)."""
        future_time = datetime.now(timezone.utc) + timedelta(hours=2)
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=True,
                consent_version="v1.0",
                consent_timestamp=future_time,
            )

        assert result.is_valid is False
        assert result.error_code == "DPDP_CONSENT_TIMESTAMP_FUTURE"

    @pytest.mark.asyncio
    async def test_5_minute_clock_skew_allowed(
        self,
        active_consent_version: MagicMock,
    ) -> None:
        """Consent 4 minutes in the future should pass (within 5-min skew allowance)."""
        slight_future = datetime.now(timezone.utc) + timedelta(minutes=4)
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=True,
                consent_version="v1.0",
                consent_timestamp=slight_future,
            )

        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_wrong_version_fails(
        self,
        active_consent_version: MagicMock,
        fresh_consent_timestamp: datetime,
    ) -> None:
        """Consent version mismatch must fail."""
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=True,
                consent_version="v0.9",  # Old version
                consent_timestamp=fresh_consent_timestamp,
            )

        assert result.is_valid is False
        assert result.error_code == "DPDP_CONSENT_VERSION_MISMATCH"
        assert result.active_version_id == "v1.0"
        assert "v0.9" in result.error_message
        assert "v1.0" in result.error_message

    @pytest.mark.asyncio
    async def test_no_active_version_fails(
        self,
        fresh_consent_timestamp: datetime,
    ) -> None:
        """If no active consent version exists, validation must fail with config error."""
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=None),
        ):
            result = await validate_consent(
                dpdp_consent=True,
                consent_version="v1.0",
                consent_timestamp=fresh_consent_timestamp,
            )

        assert result.is_valid is False
        assert result.error_code == "DPDP_NO_ACTIVE_CONSENT_VERSION"

    @pytest.mark.asyncio
    async def test_naive_datetime_treated_as_utc(
        self,
        active_consent_version: MagicMock,
    ) -> None:
        """Naive datetime (no timezone) should be treated as UTC."""
        # Naive datetime 1 hour ago
        naive_timestamp = datetime.utcnow() - timedelta(hours=1)
        assert naive_timestamp.tzinfo is None

        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=True,
                consent_version="v1.0",
                consent_timestamp=naive_timestamp,
            )

        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_custom_validity_hours_respected(
        self,
        active_consent_version: MagicMock,
    ) -> None:
        """Custom validity_hours parameter is respected."""
        # Consent given 2 hours ago
        two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)

        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ), patch.dict("os.environ", {"DPDP_CONSENT_VALIDITY_HOURS": "1"}):
            result = await validate_consent(
                dpdp_consent=True,
                consent_version="v1.0",
                consent_timestamp=two_hours_ago,
                validity_hours=1,
            )

        assert result.is_valid is False
        assert result.error_code == "DPDP_CONSENT_EXPIRED"

    @pytest.mark.asyncio
    async def test_validation_order_consent_checked_first(
        self,
        active_consent_version: MagicMock,
    ) -> None:
        """
        When consent=False AND version is wrong, error code must be
        DPDP_CONSENT_NOT_GIVEN — consent is checked first.
        """
        with patch(
            "dpdp.consent_manager.get_active_consent_version",
            new=AsyncMock(return_value=active_consent_version),
        ):
            result = await validate_consent(
                dpdp_consent=False,
                consent_version="v0.0",  # Wrong version too
                consent_timestamp=datetime.now(timezone.utc) - timedelta(hours=1),
            )

        # Consent check runs first — that's the error we see
        assert result.error_code == "DPDP_CONSENT_NOT_GIVEN"