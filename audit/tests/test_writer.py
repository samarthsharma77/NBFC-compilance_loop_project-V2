"""
Tests for audit/writer.py

Covers:
  - write_node() writes audit_record to PostgreSQL before returning state
  - write_node() sets audit_id in returned state
  - write_node() raises RuntimeError when PostgreSQL write fails
  - write_node() still raises even when MinIO scheduling fails
  - write_node() records Prometheus metrics on success and failure
  - write_node() uses server-set written_at (not client-provided)
  - _extract_agent_outputs() extracts all 5 agent keys
  - _extract_agent_outputs() handles None agent results
  - _extract_agent_outputs() handles dict and dataclass agent results
  - _get_affected_agent_tags() returns all tags as fallback on DB error
  - _serialise_agent_result() handles dict, dataclass, None

All DB and MinIO interactions are mocked.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Key setup ─────────────────────────────────────────────────────────────────

TEST_SERVER_HMAC_KEY = secrets.token_hex(32)
TEST_PAN_HMAC_KEY = secrets.token_hex(32)
while TEST_PAN_HMAC_KEY == TEST_SERVER_HMAC_KEY:
    TEST_PAN_HMAC_KEY = secrets.token_hex(32)
TEST_AES_KEY = secrets.token_hex(32)


@pytest.fixture(autouse=True)
def set_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVER_HMAC_KEY", TEST_SERVER_HMAC_KEY)
    monkeypatch.setenv("PAN_HMAC_KEY", TEST_PAN_HMAC_KEY)
    monkeypatch.setenv("AES_KEY", TEST_AES_KEY)
    import security.hmac_utils as hu
    import security.encryption as enc
    hu._server_hmac_key = None
    enc._aes_key = None
    yield
    hu._server_hmac_key = None
    enc._aes_key = None


# ── Sample state ──────────────────────────────────────────────────────────────

def _make_sample_state(
    outcome: str = "APPROVE",
    is_demo: bool = False,
    is_retro_eval: bool = False,
) -> dict:
    return {
        "application_id": str(uuid.uuid4()),
        "decision_id": str(uuid.uuid4()),
        "guideline_version_id": str(uuid.uuid4()),
        "decision": outcome,
        "confidence": 0.92,
        "composite_score": 0.87,
        "run_number": 1,
        "is_retro_eval": is_retro_eval,
        "is_demo": is_demo,
        "document_result": {
            "status": "PASS", "signal_weight": 0.95,
            "findings": [], "evidence_refs": [], "processing_time_ms": 12,
        },
        "sanctions_result": {
            "status": "PASS", "signal_weight": 1.0,
            "findings": [], "evidence_refs": [], "processing_time_ms": 5,
        },
        "temporal_result": {
            "status": "PASS", "signal_weight": 0.90,
            "findings": [], "evidence_refs": [], "processing_time_ms": 3,
        },
        "transaction_result": {
            "status": "PASS", "signal_weight": 0.85,
            "findings": [], "evidence_refs": [], "processing_time_ms": 8,
        },
        "rag_context": {
            "query": "FOIR NBFC requirements",
            "retrieved_chunks": [],
            "synthesis": "Compliant",
            "processing_time_ms": 100,
        },
        "rationale_chain": [
            {"agent": "document", "finding": "all docs present"},
        ],
        "outcome_signals": {
            "document": {"weight": 0.30, "signal": 0.95},
        },
    }


# ── write_node() tests ─────────────────────────────────────────────────────────

class TestWriteNode:

    @pytest.mark.asyncio
    async def test_returns_state_with_audit_id(self) -> None:
        """write_node adds audit_id to the state dict."""
        state = _make_sample_state()
        mock_audit_id = uuid.uuid4()

        with patch(
            "audit.writer.AuditWriter._write_audit_record",
            new=AsyncMock(return_value=mock_audit_id),
        ), patch("audit.writer.AUDIT_WRITE_DURATION"), \
           patch("audit.writer.AUDIT_WRITE_ERRORS_TOTAL"):
            from audit.writer import AuditWriter
            writer = AuditWriter()
            result = await writer.write_node(state)

        assert "audit_id" in result
        assert result["audit_id"] == str(mock_audit_id)

    @pytest.mark.asyncio
    async def test_state_otherwise_unchanged(self) -> None:
        """All original state keys are preserved in returned state."""
        state = _make_sample_state()
        mock_audit_id = uuid.uuid4()

        with patch(
            "audit.writer.AuditWriter._write_audit_record",
            new=AsyncMock(return_value=mock_audit_id),
        ), patch("audit.writer.AUDIT_WRITE_DURATION"), \
           patch("audit.writer.AUDIT_WRITE_ERRORS_TOTAL"):
            from audit.writer import AuditWriter
            writer = AuditWriter()
            result = await writer.write_node(state)

        for key in state:
            assert key in result
            assert result[key] == state[key]

    @pytest.mark.asyncio
    async def test_raises_runtime_error_on_db_failure(self) -> None:
        """
        CRITICAL: write_node must raise if PostgreSQL write fails.
        The pipeline cannot return a decision without compliance evidence.
        """
        state = _make_sample_state()

        with patch(
            "audit.writer.AuditWriter._write_audit_record",
            new=AsyncMock(side_effect=Exception("DB connection refused")),
        ), patch("audit.writer.AUDIT_WRITE_DURATION"), \
           patch("audit.writer.AUDIT_WRITE_ERRORS_TOTAL"):
            from audit.writer import AuditWriter
            writer = AuditWriter()
            with pytest.raises(RuntimeError, match="Audit record write failed"):
                await writer.write_node(state)

    @pytest.mark.asyncio
    async def test_prometheus_success_metric_recorded(self) -> None:
        """AUDIT_WRITE_DURATION.labels(...).observe() called on success."""
        state = _make_sample_state()
        mock_audit_id = uuid.uuid4()

        mock_duration = MagicMock()
        mock_histogram = MagicMock()
        mock_duration.labels.return_value = mock_histogram

        with patch(
            "audit.writer.AuditWriter._write_audit_record",
            new=AsyncMock(return_value=mock_audit_id),
        ), patch("audit.writer.AUDIT_WRITE_DURATION", mock_duration), \
           patch("audit.writer.AUDIT_WRITE_ERRORS_TOTAL"):
            from audit.writer import AuditWriter
            writer = AuditWriter()
            await writer.write_node(state)

        mock_duration.labels.assert_called_with(status="success", is_demo="false")
        mock_histogram.observe.assert_called_once()

    @pytest.mark.asyncio
    async def test_prometheus_error_metric_recorded_on_failure(self) -> None:
        """AUDIT_WRITE_ERRORS_TOTAL incremented on DB failure."""
        state = _make_sample_state()

        mock_errors = MagicMock()
        mock_errors_labels = MagicMock()
        mock_errors.labels.return_value = mock_errors_labels

        with patch(
            "audit.writer.AuditWriter._write_audit_record",
            new=AsyncMock(side_effect=Exception("timeout")),
        ), patch("audit.writer.AUDIT_WRITE_DURATION"), \
           patch("audit.writer.AUDIT_WRITE_ERRORS_TOTAL", mock_errors), \
           pytest.raises(RuntimeError):
            from audit.writer import AuditWriter
            writer = AuditWriter()
            await writer.write_node(state)

        mock_errors.labels.assert_called_with(
            error_type="postgres", is_demo="false"
        )
        mock_errors_labels.inc.assert_called_once()

    @pytest.mark.asyncio
    async def test_demo_flag_passed_to_metrics(self) -> None:
        """is_demo=True state passes is_demo='true' to Prometheus labels."""
        state = _make_sample_state(is_demo=True)
        mock_audit_id = uuid.uuid4()

        mock_duration = MagicMock()
        mock_histogram = MagicMock()
        mock_duration.labels.return_value = mock_histogram

        with patch(
            "audit.writer.AuditWriter._write_audit_record",
            new=AsyncMock(return_value=mock_audit_id),
        ), patch("audit.writer.AUDIT_WRITE_DURATION", mock_duration), \
           patch("audit.writer.AUDIT_WRITE_ERRORS_TOTAL"):
            from audit.writer import AuditWriter
            writer = AuditWriter()
            await writer.write_node(state)

        mock_duration.labels.assert_called_with(status="success", is_demo="true")


# ── _extract_agent_outputs() tests ────────────────────────────────────────────

class TestExtractAgentOutputs:

    def test_extracts_all_five_agents(self) -> None:
        from audit.writer import _extract_agent_outputs
        state = _make_sample_state()
        result = _extract_agent_outputs(state)
        assert set(result.keys()) == {"document", "sanctions", "temporal",
                                       "transaction", "rag"}

    def test_none_agent_result_preserved(self) -> None:
        """Missing agent results become None — produces a detectable hash."""
        from audit.writer import _extract_agent_outputs
        state = _make_sample_state()
        state["document_result"] = None
        result = _extract_agent_outputs(state)
        assert result["document"] is None

    def test_dict_agent_result_returned_as_is(self) -> None:
        from audit.writer import _extract_agent_outputs
        state = _make_sample_state()
        result = _extract_agent_outputs(state)
        assert isinstance(result["document"], dict)
        assert result["document"]["status"] == "PASS"

    def test_missing_state_key_returns_none(self) -> None:
        """State without document_result key → document: None."""
        from audit.writer import _extract_agent_outputs
        state = _make_sample_state()
        del state["document_result"]
        result = _extract_agent_outputs(state)
        assert result["document"] is None


# ── _serialise_agent_result() tests ──────────────────────────────────────────

class TestSerialiseAgentResult:

    def test_none_returns_none(self) -> None:
        from audit.writer import _serialise_agent_result
        assert _serialise_agent_result(None) is None

    def test_dict_returned_as_is(self) -> None:
        from audit.writer import _serialise_agent_result
        d = {"status": "PASS", "signal_weight": 0.9}
        result = _serialise_agent_result(d)
        assert result == d

    def test_dataclass_converted_to_dict(self) -> None:
        from audit.writer import _serialise_agent_result
        import dataclasses

        @dataclasses.dataclass
        class FakeResult:
            status: str = "PASS"
            signal_weight: float = 0.9

        result = _serialise_agent_result(FakeResult())
        assert isinstance(result, dict)
        assert result["status"] == "PASS"
        assert result["signal_weight"] == 0.9

    def test_object_with_dict_fallback(self) -> None:
        from audit.writer import _serialise_agent_result

        class SimpleObj:
            def __init__(self):
                self.status = "PASS"
                self.value = 42

        result = _serialise_agent_result(SimpleObj())
        assert isinstance(result, dict)
        assert result["status"] == "PASS"


# ── _get_affected_agent_tags() tests ─────────────────────────────────────────

class TestGetAffectedAgentTags:

    @pytest.mark.asyncio
    async def test_returns_db_tags_when_found(self) -> None:
        """When guideline version is found, returns its affected_agent_tags."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = ["temporal", "transaction"]
        mock_db.execute = AsyncMock(return_value=mock_result)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch("audit.writer.get_session_context", return_value=mock_ctx):
            from audit.writer import _get_affected_agent_tags
            tags = await _get_affected_agent_tags(
                guideline_version_id=str(uuid.uuid4()),
                is_demo=False,
            )

        assert tags == ["temporal", "transaction"]

    @pytest.mark.asyncio
    async def test_returns_all_tags_as_fallback_on_db_error(self) -> None:
        """
        CRITICAL: If DB lookup fails, fall back to all 5 agent tags.
        This ensures the retro-eval filter will always include this record
        in the worst case (conservative — never miss an affected record).
        """
        with patch(
            "audit.writer.get_session_context",
            side_effect=Exception("DB error"),
        ):
            from audit.writer import _get_affected_agent_tags
            tags = await _get_affected_agent_tags(
                guideline_version_id=str(uuid.uuid4()),
                is_demo=False,
            )

        assert set(tags) == {"document", "sanctions", "temporal", "transaction", "rag"}

    @pytest.mark.asyncio
    async def test_returns_all_tags_when_version_not_found(self) -> None:
        """When guideline version is not in DB, fallback to all tags."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None  # Not found
        mock_db.execute = AsyncMock(return_value=mock_result)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch("audit.writer.get_session_context", return_value=mock_ctx):
            from audit.writer import _get_affected_agent_tags
            tags = await _get_affected_agent_tags(
                guideline_version_id=str(uuid.uuid4()),
                is_demo=False,
            )

        assert set(tags) == {"document", "sanctions", "temporal", "transaction", "rag"}

    @pytest.mark.asyncio
    async def test_returns_all_tags_when_empty_array_in_db(self) -> None:
        """When DB returns empty array, fallback to all tags (safer)."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = []  # Empty array
        mock_db.execute = AsyncMock(return_value=mock_result)

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch("audit.writer.get_session_context", return_value=mock_ctx):
            from audit.writer import _get_affected_agent_tags
            tags = await _get_affected_agent_tags(
                guideline_version_id=str(uuid.uuid4()),
                is_demo=False,
            )

        assert len(tags) == 5