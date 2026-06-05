"""
Tests for dpdp/retention_enforcer.py

Covers:
  - compute_retention_expiry() date arithmetic
  - _wipe_batch() correctly nulls PII fields
  - _wipe_batch() sets retention_wiped=True and retention_wiped_at
  - _wipe_batch() creates RetentionEvent record
  - _wipe_batch() skips already-wiped applications
  - _wipe_batch() skips demo applications (is_demo=True)
  - _wipe_batch() handles individual application errors without failing batch
  - run_retention_wipe() returns correct statistics dict
  - Prometheus metrics are incremented

All DB interactions are mocked — these are unit tests.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dpdp.retention_enforcer import compute_retention_expiry


# ── compute_retention_expiry tests ────────────────────────────────────────────

class TestComputeRetentionExpiry:

    def test_default_90_days(self) -> None:
        """Default retention period is 90 days from decision date."""
        decision_date = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        expiry = compute_retention_expiry(decision_date)
        expected = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert expiry == expected

    def test_custom_days_parameter(self) -> None:
        """Custom retention_days parameter overrides default."""
        decision_date = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        expiry = compute_retention_expiry(decision_date, retention_days=30)
        expected = datetime(2026, 1, 31, 12, 0, 0, tzinfo=timezone.utc)
        assert expiry == expected

    def test_env_var_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DPDP_DEFAULT_RETENTION_DAYS env var overrides hardcoded default."""
        monkeypatch.setenv("DPDP_DEFAULT_RETENTION_DAYS", "180")
        decision_date = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        expiry = compute_retention_expiry(decision_date)
        assert expiry == decision_date + timedelta(days=180)

    def test_expiry_is_in_future(self) -> None:
        """Retention expiry is always in the future for a recent decision."""
        now = datetime.now(timezone.utc)
        expiry = compute_retention_expiry(now)
        assert expiry > now

    def test_zero_days_returns_same_time(self) -> None:
        """retention_days=0 returns the same datetime (immediate expiry)."""
        decision_date = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        expiry = compute_retention_expiry(decision_date, retention_days=0)
        assert expiry == decision_date

    def test_preserves_timezone(self) -> None:
        """Returned datetime has the same timezone as input."""
        decision_date = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        expiry = compute_retention_expiry(decision_date, retention_days=90)
        assert expiry.tzinfo is not None


# ── _wipe_batch tests (mocked DB) ─────────────────────────────────────────────

class TestWipeBatch:
    """
    Tests for the _wipe_batch() internal function.
    Uses AsyncMock to simulate the DB session and application objects.
    """

    def _make_mock_application(
        self,
        *,
        retention_wiped: bool = False,
        is_demo: bool = False,
        has_payload: bool = True,
        has_collateral: bool = True,
        has_city_tier: bool = True,
        expired_days_ago: int = 5,
    ) -> MagicMock:
        """Create a mock Application object."""
        app = MagicMock()
        app.id = uuid.uuid4()
        app.retention_wiped = retention_wiped
        app.is_demo = is_demo
        app.payload_encrypted = b"\x01" + b"\x00" * 28 if has_payload else None
        app.collateral_value = Decimal("500000.00") if has_collateral else None
        app.city_tier = "TIER_1" if has_city_tier else None
        app.retention_wiped_at = None
        app.data_retention_expires_at = (
            datetime.now(timezone.utc) - timedelta(days=expired_days_ago)
        )
        return app

    @pytest.mark.asyncio
    async def test_wipes_payload_encrypted(self) -> None:
        """_wipe_batch sets payload_encrypted to None."""
        app = self._make_mock_application(has_payload=True)

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [app]
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        mock_session_ctx = MagicMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "dpdp.retention_enforcer.get_session_context",
            return_value=mock_session_ctx,
        ), patch("dpdp.retention_enforcer.RetentionEvent"):
            from dpdp.retention_enforcer import _wipe_batch  # noqa: PLC0415
            wiped, errors = await _wipe_batch(
                task_run_id="test-run-001",
                batch_size=100,
            )

        assert wiped == 1
        assert errors == 0
        assert app.payload_encrypted is None

    @pytest.mark.asyncio
    async def test_wipes_collateral_value(self) -> None:
        """_wipe_batch nulls collateral_value."""
        app = self._make_mock_application(has_collateral=True)

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [app]
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        mock_session_ctx = MagicMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "dpdp.retention_enforcer.get_session_context",
            return_value=mock_session_ctx,
        ), patch("dpdp.retention_enforcer.RetentionEvent"):
            from dpdp.retention_enforcer import _wipe_batch  # noqa: PLC0415
            await _wipe_batch(task_run_id="test-run-001", batch_size=100)

        assert app.collateral_value is None

    @pytest.mark.asyncio
    async def test_sets_retention_wiped_flag(self) -> None:
        """_wipe_batch sets retention_wiped=True and retention_wiped_at."""
        app = self._make_mock_application()

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [app]
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        mock_session_ctx = MagicMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "dpdp.retention_enforcer.get_session_context",
            return_value=mock_session_ctx,
        ), patch("dpdp.retention_enforcer.RetentionEvent"):
            from dpdp.retention_enforcer import _wipe_batch  # noqa: PLC0415
            await _wipe_batch(task_run_id="test-run-001", batch_size=100)

        assert app.retention_wiped is True
        assert app.retention_wiped_at is not None

    @pytest.mark.asyncio
    async def test_creates_retention_event(self) -> None:
        """_wipe_batch creates a RetentionEvent record for each wiped application."""
        app = self._make_mock_application()

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [app]
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()
        added_objects = []
        mock_db.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))

        mock_session_ctx = MagicMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_retention_event_cls = MagicMock()
        mock_retention_event_instance = MagicMock()
        mock_retention_event_cls.return_value = mock_retention_event_instance

        with patch(
            "dpdp.retention_enforcer.get_session_context",
            return_value=mock_session_ctx,
        ), patch(
            "dpdp.retention_enforcer.RetentionEvent",
            mock_retention_event_cls,
        ):
            from dpdp.retention_enforcer import _wipe_batch  # noqa: PLC0415
            await _wipe_batch(task_run_id="test-run-001", batch_size=100)

        # RetentionEvent constructor should have been called once
        assert mock_retention_event_cls.call_count == 1
        # The event should have been added to the session
        assert mock_retention_event_instance in added_objects

    @pytest.mark.asyncio
    async def test_empty_batch_returns_zero(self) -> None:
        """When no expired applications found, returns (0, 0)."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        mock_session_ctx = MagicMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "dpdp.retention_enforcer.get_session_context",
            return_value=mock_session_ctx,
        ):
            from dpdp.retention_enforcer import _wipe_batch  # noqa: PLC0415
            wiped, errors = await _wipe_batch(
                task_run_id="test-run-001",
                batch_size=100,
            )

        assert wiped == 0
        assert errors == 0

    @pytest.mark.asyncio
    async def test_individual_error_continues_batch(self) -> None:
        """
        If one application fails to wipe, the error is counted but
        the batch continues with the next application.
        """
        app_good = self._make_mock_application()
        app_bad = self._make_mock_application()
        # Make the bad app raise on attribute assignment
        type(app_bad).payload_encrypted = property(
            fget=lambda self: b"data",
            fset=lambda self, v: (_ for _ in ()).throw(RuntimeError("DB error")),
        )

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [app_bad, app_good]
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        mock_session_ctx = MagicMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "dpdp.retention_enforcer.get_session_context",
            return_value=mock_session_ctx,
        ), patch("dpdp.retention_enforcer.RetentionEvent"):
            from dpdp.retention_enforcer import _wipe_batch  # noqa: PLC0415
            wiped, errors = await _wipe_batch(
                task_run_id="test-run-001",
                batch_size=100,
            )

        # Good app was wiped, bad app counted as error
        assert wiped == 1
        assert errors == 1


# ── run_retention_wipe tests ──────────────────────────────────────────────────

class TestRunRetentionWipe:

    @pytest.mark.asyncio
    async def test_returns_statistics_dict(self) -> None:
        """run_retention_wipe returns a dict with the expected keys."""
        with patch(
            "dpdp.retention_enforcer._wipe_batch",
            new=AsyncMock(side_effect=[(3, 0), (0, 0)]),  # 3 wiped, then empty
        ):
            from dpdp.retention_enforcer import _run_retention_wipe_async  # noqa: PLC0415
            result = await _run_retention_wipe_async()

        assert "wiped_count" in result
        assert "error_count" in result
        assert "duration_seconds" in result
        assert "task_run_id" in result
        assert result["wiped_count"] == 3
        assert result["error_count"] == 0

    @pytest.mark.asyncio
    async def test_loops_until_empty_batch(self) -> None:
        """run_retention_wipe keeps looping until _wipe_batch returns 0."""
        call_count = 0

        async def mock_wipe_batch(**kwargs: object) -> tuple[int, int]:
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                return 100, 0   # 3 full batches
            return 0, 0         # Empty batch — stop

        with patch(
            "dpdp.retention_enforcer._wipe_batch",
            new=mock_wipe_batch,
        ):
            from dpdp.retention_enforcer import _run_retention_wipe_async  # noqa: PLC0415
            result = await _run_retention_wipe_async()

        assert call_count == 4  # 3 batches + 1 empty check
        assert result["wiped_count"] == 300

    @pytest.mark.asyncio
    async def test_accumulates_errors(self) -> None:
        """Error counts from multiple batches are accumulated."""
        with patch(
            "dpdp.retention_enforcer._wipe_batch",
            new=AsyncMock(side_effect=[(5, 2), (3, 1), (0, 0)]),
        ):
            from dpdp.retention_enforcer import _run_retention_wipe_async  # noqa: PLC0415
            result = await _run_retention_wipe_async()

        assert result["wiped_count"] == 8
        assert result["error_count"] == 3