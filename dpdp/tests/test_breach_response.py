"""
Tests for dpdp/breach_response.py

Covers:
  - breach_response() requires application_id OR time_range
  - breach_response() calls break_glass PostgreSQL procedure
  - breach_response() freezes retro-eval jobs
  - breach_response() queues DPDP Board notification
  - breach_response() returns BreachReport with correct structure
  - _assess_data_categories() returns correct categories per severity
  - _get_recommended_actions() includes board notification for HIGH/CRITICAL
  - BreachScope and BreachReport dataclasses
  - Prometheus metric is incremented on breach

All external calls (DB, Redis, Celery) are mocked.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dpdp.breach_response import (
    BreachReport,
    BreachScope,
    _assess_data_categories,
    _get_recommended_actions,
)


# ── BreachScope and BreachReport dataclass tests ──────────────────────────────

class TestBreachDataclasses:

    def test_breach_scope_defaults(self) -> None:
        scope = BreachScope()
        assert scope.application_ids == []
        assert scope.estimated_records_affected == 0
        assert scope.data_categories_affected == []
        assert scope.breach_detected_at is not None

    def test_breach_scope_with_values(self) -> None:
        app_ids = [str(uuid.uuid4())]
        scope = BreachScope(
            application_ids=app_ids,
            estimated_records_affected=5,
            data_categories_affected=["PII", "financial"],
        )
        assert scope.application_ids == app_ids
        assert scope.estimated_records_affected == 5

    def test_breach_report_fields(self) -> None:
        report = BreachReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.now(timezone.utc),
            breach_scope=BreachScope(),
            records_flagged=10,
            notifications_queued=2,
            retro_eval_jobs_frozen=3,
            data_categories=["PII"],
            recommended_actions=["action1"],
            severity="HIGH",
        )
        assert report.records_flagged == 10
        assert report.notifications_queued == 2
        assert report.severity == "HIGH"


# ── _assess_data_categories tests ─────────────────────────────────────────────

class TestAssessDataCategories:

    def test_low_severity_base_categories(self) -> None:
        cats = _assess_data_categories("LOW")
        assert "Application identifiers" in cats
        assert "Decision outcomes" in cats
        # Should NOT include financial data for LOW severity
        assert not any("financial" in c.lower() for c in cats)

    def test_high_severity_includes_financial(self) -> None:
        cats = _assess_data_categories("HIGH")
        assert any("financial" in c.lower() or "income" in c.lower() for c in cats)
        assert any("encrypted" in c.lower() for c in cats)

    def test_critical_severity_includes_documents(self) -> None:
        cats = _assess_data_categories("CRITICAL")
        assert any("document" in c.lower() or "kyc" in c.lower() for c in cats)

    def test_medium_severity_similar_to_high(self) -> None:
        cats_medium = _assess_data_categories("MEDIUM")
        cats_low = _assess_data_categories("LOW")
        # MEDIUM should have more categories than LOW
        assert len(cats_medium) >= len(cats_low)

    def test_all_severities_return_list(self) -> None:
        for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            cats = _assess_data_categories(severity)
            assert isinstance(cats, list)
            assert len(cats) > 0


# ── _get_recommended_actions tests ────────────────────────────────────────────

class TestGetRecommendedActions:

    def test_high_severity_includes_board_notification(self) -> None:
        """HIGH severity must include mandatory DPDP Board notification action."""
        actions = _get_recommended_actions("HIGH")
        board_action = any("board" in a.lower() or "dpdp" in a.lower() for a in actions)
        assert board_action, "HIGH severity must include DPDP Board notification action"

    def test_critical_severity_includes_law_enforcement(self) -> None:
        """CRITICAL severity should mention law enforcement."""
        actions = _get_recommended_actions("CRITICAL")
        law_enforcement = any("law enforcement" in a.lower() for a in actions)
        assert law_enforcement

    def test_low_severity_no_mandatory_board_notification(self) -> None:
        """LOW severity should not have MANDATORY board notification."""
        actions = _get_recommended_actions("LOW")
        mandatory_board = any(
            "MANDATORY" in a and "board" in a.lower() for a in actions
        )
        assert not mandatory_board

    def test_all_severities_include_review_action(self) -> None:
        """All severities should include a breach scope review action."""
        for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            actions = _get_recommended_actions(severity)
            has_review = any(
                "review" in a.lower() or "assess" in a.lower()
                for a in actions
            )
            assert has_review, f"Severity {severity} missing review action"

    def test_all_severities_return_list(self) -> None:
        for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            actions = _get_recommended_actions(severity)
            assert isinstance(actions, list)
            assert len(actions) >= 3


# ── breach_response() integration tests (mocked) ─────────────────────────────

class TestBreachResponse:

    @pytest.mark.asyncio
    async def test_requires_application_id_or_time_range(self) -> None:
        """breach_response with no args raises ValueError."""
        from dpdp.breach_response import breach_response  # noqa: PLC0415
        with pytest.raises(ValueError, match="Must provide either"):
            await breach_response()

    @pytest.mark.asyncio
    async def test_requires_both_time_range_fields(self) -> None:
        """Providing only time_range_start without end raises ValueError."""
        from dpdp.breach_response import breach_response  # noqa: PLC0415
        with pytest.raises(ValueError, match="Must provide either"):
            await breach_response(
                time_range_start=datetime.now(timezone.utc),
                # time_range_end missing
            )

    @pytest.mark.asyncio
    async def test_single_application_breach(self) -> None:
        """breach_response for a single application_id returns BreachReport."""
        app_id = str(uuid.uuid4())

        with patch(
            "dpdp.breach_response._call_break_glass_procedure",
            new=AsyncMock(return_value=(3, 1)),
        ), patch(
            "dpdp.breach_response._freeze_retro_eval_jobs",
            new=AsyncMock(return_value=2),
        ), patch(
            "dpdp.breach_response._get_affected_application_ids",
            new=AsyncMock(return_value=[app_id]),
        ), patch(
            "dpdp.breach_response._queue_board_notification",
            new=AsyncMock(),
        ):
            from dpdp.breach_response import breach_response  # noqa: PLC0415
            report = await breach_response(
                application_id=app_id,
                severity="HIGH",
                triggered_by="admin_user",
            )

        assert isinstance(report, BreachReport)
        assert report.records_flagged == 3
        assert report.notifications_queued == 1
        assert report.retro_eval_jobs_frozen == 2
        assert report.severity == "HIGH"
        assert report.report_id is not None
        assert report.generated_at is not None

    @pytest.mark.asyncio
    async def test_time_range_breach(self) -> None:
        """breach_response with time range returns BreachReport."""
        start = datetime.now(timezone.utc) - timedelta(hours=2)
        end = datetime.now(timezone.utc)
        affected_ids = [str(uuid.uuid4()) for _ in range(5)]

        with patch(
            "dpdp.breach_response._call_break_glass_procedure",
            new=AsyncMock(return_value=(15, 5)),
        ), patch(
            "dpdp.breach_response._freeze_retro_eval_jobs",
            new=AsyncMock(return_value=0),
        ), patch(
            "dpdp.breach_response._get_affected_application_ids",
            new=AsyncMock(return_value=affected_ids),
        ), patch(
            "dpdp.breach_response._queue_board_notification",
            new=AsyncMock(),
        ):
            from dpdp.breach_response import breach_response  # noqa: PLC0415
            report = await breach_response(
                time_range_start=start,
                time_range_end=end,
                severity="CRITICAL",
            )

        assert report.records_flagged == 15
        assert report.notifications_queued == 5
        assert len(report.breach_scope.application_ids) == 5

    @pytest.mark.asyncio
    async def test_board_notification_queued_for_high_severity(self) -> None:
        """_queue_board_notification is called for HIGH severity."""
        app_id = str(uuid.uuid4())
        board_notification_called = False

        async def mock_board_notification(**kwargs: object) -> None:
            nonlocal board_notification_called
            board_notification_called = True

        with patch(
            "dpdp.breach_response._call_break_glass_procedure",
            new=AsyncMock(return_value=(1, 1)),
        ), patch(
            "dpdp.breach_response._freeze_retro_eval_jobs",
            new=AsyncMock(return_value=0),
        ), patch(
            "dpdp.breach_response._get_affected_application_ids",
            new=AsyncMock(return_value=[app_id]),
        ), patch(
            "dpdp.breach_response._queue_board_notification",
            new=mock_board_notification,
        ):
            from dpdp.breach_response import breach_response  # noqa: PLC0415
            await breach_response(
                application_id=app_id,
                severity="HIGH",
            )

        assert board_notification_called

    @pytest.mark.asyncio
    async def test_report_contains_recommended_actions(self) -> None:
        """BreachReport always includes recommended_actions list."""
        app_id = str(uuid.uuid4())

        with patch(
            "dpdp.breach_response._call_break_glass_procedure",
            new=AsyncMock(return_value=(1, 1)),
        ), patch(
            "dpdp.breach_response._freeze_retro_eval_jobs",
            new=AsyncMock(return_value=0),
        ), patch(
            "dpdp.breach_response._get_affected_application_ids",
            new=AsyncMock(return_value=[app_id]),
        ), patch(
            "dpdp.breach_response._queue_board_notification",
            new=AsyncMock(),
        ):
            from dpdp.breach_response import breach_response  # noqa: PLC0415
            report = await breach_response(
                application_id=app_id,
                severity="MEDIUM",
            )

        assert isinstance(report.recommended_actions, list)
        assert len(report.recommended_actions) > 0

    @pytest.mark.asyncio
    async def test_prometheus_metric_incremented(self) -> None:
        """DPDP_BREACH_FLAGS_TOTAL counter is incremented."""
        app_id = str(uuid.uuid4())
        mock_metric = MagicMock()
        mock_labels = MagicMock()
        mock_metric.labels.return_value = mock_labels

        with patch(
            "dpdp.breach_response._call_break_glass_procedure",
            new=AsyncMock(return_value=(5, 1)),
        ), patch(
            "dpdp.breach_response._freeze_retro_eval_jobs",
            new=AsyncMock(return_value=0),
        ), patch(
            "dpdp.breach_response._get_affected_application_ids",
            new=AsyncMock(return_value=[app_id]),
        ), patch(
            "dpdp.breach_response._queue_board_notification",
            new=AsyncMock(),
        ), patch(
            "dpdp.breach_response.DPDP_BREACH_FLAGS_TOTAL",
            mock_metric,
            create=True,
        ):
            from dpdp.breach_response import breach_response  # noqa: PLC0415
            await breach_response(
                application_id=app_id,
                severity="HIGH",
            )

        mock_metric.labels.assert_called_with(is_demo="false")
        mock_labels.inc.assert_called_with(5)  # records_flagged=5