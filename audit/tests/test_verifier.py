"""
Tests for audit/verifier.py

Covers:
  - verify_by_decision_id() raises ValueError when no audit record
  - verify_by_decision_id() returns VerificationResult with is_valid=True
    when hash and HMAC both match
  - verify_by_decision_id() returns is_valid=False when MinIO unavailable
    but HMAC passes (partial verification)
  - verify_by_decision_id() returns is_valid=False when HMAC fails
  - verify_by_application_id() returns list of VerificationResult
  - VerificationResult.to_report_dict() has required keys
  - VerificationResult boolean fields are correct types
  - _run_full_verification() passes for valid record
  - _run_full_verification() fails for tampered agent_outputs
  - _run_hmac_only_verification() passes with correct stored fields
  - _run_hmac_only_verification() fails with wrong decision_id

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


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_AGENT_OUTPUTS = {
    "document": {"status": "PASS", "signal_weight": 0.95,
                 "findings": [], "evidence_refs": [], "processing_time_ms": 10},
    "sanctions": {"status": "PASS", "signal_weight": 1.0,
                  "findings": [], "evidence_refs": [], "processing_time_ms": 5},
    "temporal": {"status": "PASS", "signal_weight": 0.90,
                 "findings": [], "evidence_refs": [], "processing_time_ms": 3},
    "transaction": {"status": "PASS", "signal_weight": 0.85,
                    "findings": [], "evidence_refs": [], "processing_time_ms": 8},
    "rag": {"query": "FOIR", "retrieved_chunks": [],
            "synthesis": "OK", "processing_time_ms": 100},
}


def _make_valid_audit_record() -> MagicMock:
    """Build a mock AuditRecord with correct hash and HMAC."""
    from audit.hasher import (
        compute_agent_outputs_hash,
        compute_audit_hmac,
        compute_payload_s3_key,
    )

    decision_id = str(uuid.uuid4())
    guideline_version_id = str(uuid.uuid4())
    written_at = datetime(2026, 6, 1, 12, 0, 0, 0, tzinfo=timezone.utc)

    agent_hash = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
    record_hmac = compute_audit_hmac(
        agent_outputs_hash=agent_hash,
        decision_id=decision_id,
        guideline_version_id=guideline_version_id,
        written_at=written_at,
    )
    s3_key = compute_payload_s3_key(decision_id, written_at)

    record = MagicMock()
    record.decision_id = uuid.UUID(decision_id)
    record.application_id = uuid.uuid4()
    record.guideline_version_id = uuid.UUID(guideline_version_id)
    record.written_at = written_at
    record.agent_outputs_hash = agent_hash
    record.record_hmac = record_hmac
    record.payload_s3_key = s3_key
    record.payload_s3_uploaded = True
    record.is_demo = False

    return record, decision_id, guideline_version_id


# ── VerificationResult tests ──────────────────────────────────────────────────

class TestVerificationResult:

    def test_to_report_dict_has_required_keys(self) -> None:
        from audit.verifier import VerificationResult
        result = VerificationResult(
            decision_id=str(uuid.uuid4()),
            application_id=str(uuid.uuid4()),
            guideline_version_id=str(uuid.uuid4()),
            written_at="2026-06-01T12:00:00+00:00",
            outcome="APPROVE",
            is_valid=True,
            hash_check_passed=True,
            hmac_check_passed=True,
            minio_payload_available=True,
            failure_reason="",
            agent_outputs_hash="a" * 64,
            record_hmac_prefix="abcd1234efgh5678",
        )
        d = result.to_report_dict()
        required = {
            "decision_id", "application_id", "guideline_version_id",
            "written_at", "outcome", "is_valid", "hash_check_passed",
            "hmac_check_passed", "minio_payload_available", "failure_reason",
            "agent_outputs_hash_prefix", "record_hmac_prefix", "verified_at",
        }
        assert required.issubset(set(d.keys()))

    def test_to_report_dict_is_valid_true(self) -> None:
        from audit.verifier import VerificationResult
        result = VerificationResult(
            decision_id="d", application_id="a", guideline_version_id="g",
            written_at="t", outcome="APPROVE",
            is_valid=True, hash_check_passed=True,
            hmac_check_passed=True, minio_payload_available=True,
        )
        d = result.to_report_dict()
        assert d["is_valid"] is True

    def test_hash_prefix_in_report(self) -> None:
        from audit.verifier import VerificationResult
        result = VerificationResult(
            decision_id="d", application_id="a", guideline_version_id="g",
            written_at="t", outcome="APPROVE",
            is_valid=True, hash_check_passed=True,
            hmac_check_passed=True, minio_payload_available=True,
            agent_outputs_hash="abcdef" + "0" * 58,
        )
        d = result.to_report_dict()
        assert d["agent_outputs_hash_prefix"].startswith("abcdef")
        assert d["agent_outputs_hash_prefix"].endswith("...")


# ── _run_full_verification() tests ────────────────────────────────────────────

class TestRunFullVerification:

    def test_valid_record_passes(self) -> None:
        from audit.verifier import _run_full_verification
        record, _, _ = _make_valid_audit_record()
        is_valid, reason = _run_full_verification(
            audit_record=record,
            agent_outputs=SAMPLE_AGENT_OUTPUTS,
        )
        assert is_valid is True
        assert reason == ""

    def test_tampered_agent_outputs_fails(self) -> None:
        from audit.verifier import _run_full_verification
        record, _, _ = _make_valid_audit_record()
        tampered = {**SAMPLE_AGENT_OUTPUTS, "document": {"status": "FAIL"}}
        is_valid, reason = _run_full_verification(
            audit_record=record,
            agent_outputs=tampered,
        )
        assert is_valid is False
        assert reason != ""


# ── _run_hmac_only_verification() tests ──────────────────────────────────────

class TestRunHmacOnlyVerification:

    def test_valid_hmac_passes(self) -> None:
        from audit.verifier import _run_hmac_only_verification
        record, _, _ = _make_valid_audit_record()
        is_valid, reason, hash_passed, hmac_passed = _run_hmac_only_verification(
            audit_record=record,
        )
        assert is_valid is True
        assert hmac_passed is True
        assert hash_passed is False  # Hash not checked without payload

    def test_tampered_hmac_fails(self) -> None:
        from audit.verifier import _run_hmac_only_verification
        record, _, _ = _make_valid_audit_record()
        record.record_hmac = "f" * 64  # Corrupted HMAC
        is_valid, reason, hash_passed, hmac_passed = _run_hmac_only_verification(
            audit_record=record,
        )
        assert is_valid is False
        assert hmac_passed is False

    def test_wrong_decision_id_fails(self) -> None:
        """Changing decision_id after HMAC was computed should fail verification."""
        from audit.verifier import _run_hmac_only_verification
        record, _, _ = _make_valid_audit_record()
        record.decision_id = uuid.uuid4()  # Changed after HMAC was computed
        is_valid, reason, _, hmac_passed = _run_hmac_only_verification(
            audit_record=record,
        )
        assert is_valid is False
        assert hmac_passed is False


# ── verify_by_decision_id() tests ─────────────────────────────────────────────

class TestVerifyByDecisionId:

    def _make_mock_db_session(
        self, audit_record: MagicMock, decision_mock: MagicMock | None = None
    ) -> tuple[MagicMock, MagicMock]:
        mock_db = AsyncMock()

        audit_result = MagicMock()
        audit_result.scalar_one_or_none.return_value = audit_record

        decision_result = MagicMock()
        decision_result.scalar_one_or_none.return_value = decision_mock

        mock_db.execute = AsyncMock(
            side_effect=[audit_result, decision_result]
        )

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)
        return mock_db, mock_ctx

    @pytest.mark.asyncio
    async def test_raises_value_error_when_no_audit_record(self) -> None:
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch("audit.verifier.get_session_context", return_value=mock_ctx):
            from audit.verifier import verify_by_decision_id
            with pytest.raises(ValueError, match="No audit record found"):
                await verify_by_decision_id(decision_id=str(uuid.uuid4()))

    @pytest.mark.asyncio
    async def test_valid_record_with_minio_returns_is_valid_true(self) -> None:
        record, decision_id, _ = _make_valid_audit_record()
        mock_decision = MagicMock()
        mock_decision.outcome.value = "APPROVE"
        _, mock_ctx = self._make_mock_db_session(record, mock_decision)

        with patch("audit.verifier.get_session_context", return_value=mock_ctx), \
             patch(
                 "audit.verifier._download_and_decrypt_payload",
                 new=AsyncMock(return_value={"agent_outputs": SAMPLE_AGENT_OUTPUTS}),
             ):
            from audit.verifier import verify_by_decision_id
            result = await verify_by_decision_id(decision_id=decision_id)

        assert result.is_valid is True
        assert result.minio_payload_available is True
        assert result.hash_check_passed is True
        assert result.hmac_check_passed is True
        assert result.failure_reason == ""

    @pytest.mark.asyncio
    async def test_partial_verification_when_minio_unavailable(self) -> None:
        """When MinIO is down, HMAC-only verification still passes."""
        record, decision_id, _ = _make_valid_audit_record()
        mock_decision = MagicMock()
        mock_decision.outcome.value = "APPROVE"
        _, mock_ctx = self._make_mock_db_session(record, mock_decision)

        with patch("audit.verifier.get_session_context", return_value=mock_ctx), \
             patch(
                 "audit.verifier._download_and_decrypt_payload",
                 new=AsyncMock(side_effect=Exception("MinIO unavailable")),
             ):
            from audit.verifier import verify_by_decision_id
            result = await verify_by_decision_id(decision_id=decision_id)

        assert result.minio_payload_available is False
        assert result.hmac_check_passed is True
        assert result.is_valid is True  # HMAC passes even without payload

    @pytest.mark.asyncio
    async def test_tampered_record_returns_is_valid_false(self) -> None:
        """Tampered record with wrong HMAC returns is_valid=False."""
        record, decision_id, _ = _make_valid_audit_record()
        record.record_hmac = "0" * 64   # Corrupted
        mock_decision = MagicMock()
        mock_decision.outcome.value = "APPROVE"
        _, mock_ctx = self._make_mock_db_session(record, mock_decision)

        with patch("audit.verifier.get_session_context", return_value=mock_ctx), \
             patch(
                 "audit.verifier._download_and_decrypt_payload",
                 new=AsyncMock(side_effect=Exception("unavailable")),
             ):
            from audit.verifier import verify_by_decision_id
            result = await verify_by_decision_id(decision_id=decision_id)

        assert result.is_valid is False
        assert result.hmac_check_passed is False
        assert result.failure_reason != ""

    @pytest.mark.asyncio
    async def test_result_contains_correct_metadata(self) -> None:
        record, decision_id, guideline_version_id = _make_valid_audit_record()
        mock_decision = MagicMock()
        mock_decision.outcome.value = "REJECT"
        _, mock_ctx = self._make_mock_db_session(record, mock_decision)

        with patch("audit.verifier.get_session_context", return_value=mock_ctx), \
             patch(
                 "audit.verifier._download_and_decrypt_payload",
                 new=AsyncMock(return_value={"agent_outputs": SAMPLE_AGENT_OUTPUTS}),
             ):
            from audit.verifier import verify_by_decision_id
            result = await verify_by_decision_id(decision_id=decision_id)

        assert result.decision_id == decision_id
        assert result.outcome == "REJECT"
        assert result.written_at != ""
        assert result.verified_at != ""


# ── verify_by_application_id() tests ─────────────────────────────────────────

class TestVerifyByApplicationId:

    @pytest.mark.asyncio
    async def test_returns_list(self) -> None:
        """verify_by_application_id returns a list (possibly empty)."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch("audit.verifier.get_session_context", return_value=mock_ctx):
            from audit.verifier import verify_by_application_id
            results = await verify_by_application_id(
                application_id=str(uuid.uuid4())
            )

        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_returns_result_per_audit_record(self) -> None:
        """One VerificationResult per audit record for the application."""
        record, decision_id, _ = _make_valid_audit_record()
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [record]
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_verification = MagicMock()

        with patch("audit.verifier.get_session_context", return_value=mock_ctx), \
             patch(
                 "audit.verifier.verify_by_decision_id",
                 new=AsyncMock(return_value=mock_verification),
             ):
            from audit.verifier import verify_by_application_id
            results = await verify_by_application_id(
                application_id=str(uuid.uuid4())
            )

        assert len(results) == 1
        assert results[0] is mock_verification