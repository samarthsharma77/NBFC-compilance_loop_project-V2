"""
Tests for audit/hasher.py

Covers:
  - compute_agent_outputs_hash() returns 64-char hex
  - compute_agent_outputs_hash() is deterministic
  - compute_agent_outputs_hash() different inputs → different hashes
  - compute_agent_outputs_hash() raises on empty dict
  - compute_audit_hmac() returns 64-char hex
  - compute_audit_hmac() is deterministic for same inputs
  - compute_audit_hmac() different decision_id → different HMAC
  - compute_payload_s3_key() correct format
  - compute_payload_s3_key() year/month routing
  - verify_audit_record_integrity() passes for valid record
  - verify_audit_record_integrity() fails on tampered agent_outputs
  - verify_audit_record_integrity() fails on tampered decision_id
  - verify_audit_record_integrity() fails on tampered written_at
  - _serialise_written_at() produces consistent ISO format
  - _serialise_written_at() handles naive datetime as UTC
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone, timedelta

import pytest

# ── Environment setup ─────────────────────────────────────────────────────────

TEST_SERVER_HMAC_KEY = secrets.token_hex(32)
TEST_PAN_HMAC_KEY = secrets.token_hex(32)
while TEST_PAN_HMAC_KEY == TEST_SERVER_HMAC_KEY:
    TEST_PAN_HMAC_KEY = secrets.token_hex(32)


@pytest.fixture(autouse=True)
def set_hmac_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVER_HMAC_KEY", TEST_SERVER_HMAC_KEY)
    monkeypatch.setenv("PAN_HMAC_KEY", TEST_PAN_HMAC_KEY)
    # Reset cached keys
    import security.hmac_utils as hu
    hu._server_hmac_key = None
    hu._server_hmac_key_previous = None
    yield
    hu._server_hmac_key = None
    hu._server_hmac_key_previous = None


# ── Sample data ───────────────────────────────────────────────────────────────

SAMPLE_AGENT_OUTPUTS = {
    "document": {
        "status": "PASS",
        "signal_weight": 0.95,
        "findings": [{"code": "DOC_PAN_PRESENT", "severity": "PASS"}],
        "evidence_refs": ["RBI_KYC_MD_2016_S3.2"],
        "processing_time_ms": 12,
    },
    "sanctions": {
        "status": "PASS",
        "signal_weight": 1.0,
        "findings": [],
        "evidence_refs": ["UNSC_LIST"],
        "processing_time_ms": 5,
    },
    "temporal": {
        "status": "PASS",
        "signal_weight": 0.90,
        "findings": [],
        "evidence_refs": [],
        "processing_time_ms": 3,
    },
    "transaction": {
        "status": "PASS",
        "signal_weight": 0.85,
        "findings": [{"code": "FOIR_WITHIN_LIMIT", "severity": "PASS"}],
        "evidence_refs": ["RBI_NBFC_FOIR_CIRCULAR"],
        "processing_time_ms": 8,
    },
    "rag": {
        "query": "FOIR NBFC unsecured loan requirements",
        "retrieved_chunks": [],
        "synthesis": "FOIR within acceptable range per RBI guidelines.",
        "processing_time_ms": 145,
    },
}

SAMPLE_DECISION_ID = str(uuid.uuid4())
SAMPLE_GUIDELINE_VERSION_ID = str(uuid.uuid4())
SAMPLE_WRITTEN_AT = datetime(2026, 6, 1, 12, 0, 0, 0, tzinfo=timezone.utc)


# ── compute_agent_outputs_hash() ──────────────────────────────────────────────

class TestComputeAgentOutputsHash:

    def test_returns_64_char_hex(self) -> None:
        from audit.hasher import compute_agent_outputs_hash
        result = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        assert isinstance(result, str)
        assert len(result) == 64
        int(result, 16)  # Must be valid hex

    def test_deterministic(self) -> None:
        from audit.hasher import compute_agent_outputs_hash
        h1 = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        h2 = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        assert h1 == h2

    def test_different_outputs_different_hash(self) -> None:
        from audit.hasher import compute_agent_outputs_hash
        modified = {**SAMPLE_AGENT_OUTPUTS}
        modified["document"] = {**SAMPLE_AGENT_OUTPUTS["document"], "signal_weight": 0.5}
        h1 = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        h2 = compute_agent_outputs_hash(modified)
        assert h1 != h2

    def test_missing_agent_different_hash(self) -> None:
        """Incomplete agent outputs produce different hash from complete set."""
        from audit.hasher import compute_agent_outputs_hash
        incomplete = {k: v for k, v in SAMPLE_AGENT_OUTPUTS.items() if k != "rag"}
        h_complete = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        h_incomplete = compute_agent_outputs_hash(incomplete)
        assert h_complete != h_incomplete

    def test_raises_on_empty_dict(self) -> None:
        from audit.hasher import compute_agent_outputs_hash
        with pytest.raises(ValueError, match="must not be empty"):
            compute_agent_outputs_hash({})

    def test_key_order_does_not_matter(self) -> None:
        """Canonical JSON sorts keys — key order shouldn't affect hash."""
        from audit.hasher import compute_agent_outputs_hash
        reordered = dict(reversed(list(SAMPLE_AGENT_OUTPUTS.items())))
        h1 = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        h2 = compute_agent_outputs_hash(reordered)
        assert h1 == h2


# ── compute_audit_hmac() ──────────────────────────────────────────────────────

class TestComputeAuditHmac:

    def test_returns_64_char_hex(self) -> None:
        from audit.hasher import compute_agent_outputs_hash, compute_audit_hmac
        agent_hash = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        result = compute_audit_hmac(
            agent_outputs_hash=agent_hash,
            decision_id=SAMPLE_DECISION_ID,
            guideline_version_id=SAMPLE_GUIDELINE_VERSION_ID,
            written_at=SAMPLE_WRITTEN_AT,
        )
        assert isinstance(result, str)
        assert len(result) == 64
        int(result, 16)

    def test_deterministic(self) -> None:
        from audit.hasher import compute_agent_outputs_hash, compute_audit_hmac
        agent_hash = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        h1 = compute_audit_hmac(agent_hash, SAMPLE_DECISION_ID,
                                SAMPLE_GUIDELINE_VERSION_ID, SAMPLE_WRITTEN_AT)
        h2 = compute_audit_hmac(agent_hash, SAMPLE_DECISION_ID,
                                SAMPLE_GUIDELINE_VERSION_ID, SAMPLE_WRITTEN_AT)
        assert h1 == h2

    def test_different_decision_id_different_hmac(self) -> None:
        from audit.hasher import compute_agent_outputs_hash, compute_audit_hmac
        agent_hash = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        h1 = compute_audit_hmac(agent_hash, SAMPLE_DECISION_ID,
                                SAMPLE_GUIDELINE_VERSION_ID, SAMPLE_WRITTEN_AT)
        h2 = compute_audit_hmac(agent_hash, str(uuid.uuid4()),
                                SAMPLE_GUIDELINE_VERSION_ID, SAMPLE_WRITTEN_AT)
        assert h1 != h2

    def test_different_written_at_different_hmac(self) -> None:
        from audit.hasher import compute_agent_outputs_hash, compute_audit_hmac
        agent_hash = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        t1 = datetime(2026, 6, 1, 12, 0, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 6, 1, 12, 0, 1, 0, tzinfo=timezone.utc)  # 1 second later
        h1 = compute_audit_hmac(agent_hash, SAMPLE_DECISION_ID,
                                SAMPLE_GUIDELINE_VERSION_ID, t1)
        h2 = compute_audit_hmac(agent_hash, SAMPLE_DECISION_ID,
                                SAMPLE_GUIDELINE_VERSION_ID, t2)
        assert h1 != h2

    def test_different_guideline_version_different_hmac(self) -> None:
        from audit.hasher import compute_agent_outputs_hash, compute_audit_hmac
        agent_hash = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        h1 = compute_audit_hmac(agent_hash, SAMPLE_DECISION_ID,
                                SAMPLE_GUIDELINE_VERSION_ID, SAMPLE_WRITTEN_AT)
        h2 = compute_audit_hmac(agent_hash, SAMPLE_DECISION_ID,
                                str(uuid.uuid4()), SAMPLE_WRITTEN_AT)
        assert h1 != h2

    def test_different_key_different_hmac(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from audit.hasher import compute_agent_outputs_hash, compute_audit_hmac
        import security.hmac_utils as hu
        agent_hash = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        h1 = compute_audit_hmac(agent_hash, SAMPLE_DECISION_ID,
                                SAMPLE_GUIDELINE_VERSION_ID, SAMPLE_WRITTEN_AT)

        monkeypatch.setenv("SERVER_HMAC_KEY", secrets.token_hex(32))
        hu._server_hmac_key = None
        h2 = compute_audit_hmac(agent_hash, SAMPLE_DECISION_ID,
                                SAMPLE_GUIDELINE_VERSION_ID, SAMPLE_WRITTEN_AT)
        assert h1 != h2


# ── compute_payload_s3_key() ──────────────────────────────────────────────────

class TestComputePayloadS3Key:

    def test_format_contains_decision_id(self) -> None:
        from audit.hasher import compute_payload_s3_key
        key = compute_payload_s3_key(SAMPLE_DECISION_ID, SAMPLE_WRITTEN_AT)
        assert SAMPLE_DECISION_ID in key

    def test_format_starts_with_audit(self) -> None:
        from audit.hasher import compute_payload_s3_key
        key = compute_payload_s3_key(SAMPLE_DECISION_ID, SAMPLE_WRITTEN_AT)
        assert key.startswith("audit/")

    def test_contains_year_and_month(self) -> None:
        from audit.hasher import compute_payload_s3_key
        dt = datetime(2026, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        key = compute_payload_s3_key("test-id", dt)
        assert "/2026/" in key
        assert "/06/" in key

    def test_ends_with_json_enc(self) -> None:
        from audit.hasher import compute_payload_s3_key
        key = compute_payload_s3_key(SAMPLE_DECISION_ID, SAMPLE_WRITTEN_AT)
        assert key.endswith(".json.enc")

    def test_full_format(self) -> None:
        from audit.hasher import compute_payload_s3_key
        dt = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        decision_id = "550e8400-e29b-41d4-a716-446655440000"
        key = compute_payload_s3_key(decision_id, dt)
        assert key == f"audit/2026/06/{decision_id}.json.enc"


# ── verify_audit_record_integrity() ──────────────────────────────────────────

class TestVerifyAuditRecordIntegrity:

    def _compute_valid_fields(self) -> tuple[str, str]:
        from audit.hasher import compute_agent_outputs_hash, compute_audit_hmac
        agent_hash = compute_agent_outputs_hash(SAMPLE_AGENT_OUTPUTS)
        record_hmac = compute_audit_hmac(
            agent_hash, SAMPLE_DECISION_ID,
            SAMPLE_GUIDELINE_VERSION_ID, SAMPLE_WRITTEN_AT
        )
        return agent_hash, record_hmac

    def test_valid_record_passes(self) -> None:
        from audit.hasher import verify_audit_record_integrity
        agent_hash, record_hmac = self._compute_valid_fields()
        is_valid, reason = verify_audit_record_integrity(
            stored_agent_outputs_hash=agent_hash,
            stored_record_hmac=record_hmac,
            agent_outputs=SAMPLE_AGENT_OUTPUTS,
            decision_id=SAMPLE_DECISION_ID,
            guideline_version_id=SAMPLE_GUIDELINE_VERSION_ID,
            written_at=SAMPLE_WRITTEN_AT,
        )
        assert is_valid is True
        assert reason == ""

    def test_tampered_agent_outputs_fails(self) -> None:
        from audit.hasher import verify_audit_record_integrity
        agent_hash, record_hmac = self._compute_valid_fields()
        tampered = {**SAMPLE_AGENT_OUTPUTS}
        tampered["document"] = {**SAMPLE_AGENT_OUTPUTS["document"], "signal_weight": 0.0}
        is_valid, reason = verify_audit_record_integrity(
            stored_agent_outputs_hash=agent_hash,
            stored_record_hmac=record_hmac,
            agent_outputs=tampered,
            decision_id=SAMPLE_DECISION_ID,
            guideline_version_id=SAMPLE_GUIDELINE_VERSION_ID,
            written_at=SAMPLE_WRITTEN_AT,
        )
        assert is_valid is False
        assert "tampered" in reason.lower() or "mismatch" in reason.lower()

    def test_tampered_decision_id_fails(self) -> None:
        from audit.hasher import verify_audit_record_integrity
        agent_hash, record_hmac = self._compute_valid_fields()
        is_valid, reason = verify_audit_record_integrity(
            stored_agent_outputs_hash=agent_hash,
            stored_record_hmac=record_hmac,
            agent_outputs=SAMPLE_AGENT_OUTPUTS,
            decision_id=str(uuid.uuid4()),  # Wrong decision_id
            guideline_version_id=SAMPLE_GUIDELINE_VERSION_ID,
            written_at=SAMPLE_WRITTEN_AT,
        )
        assert is_valid is False
        assert "hmac" in reason.lower()

    def test_tampered_guideline_version_fails(self) -> None:
        from audit.hasher import verify_audit_record_integrity
        agent_hash, record_hmac = self._compute_valid_fields()
        is_valid, reason = verify_audit_record_integrity(
            stored_agent_outputs_hash=agent_hash,
            stored_record_hmac=record_hmac,
            agent_outputs=SAMPLE_AGENT_OUTPUTS,
            decision_id=SAMPLE_DECISION_ID,
            guideline_version_id=str(uuid.uuid4()),  # Wrong version
            written_at=SAMPLE_WRITTEN_AT,
        )
        assert is_valid is False

    def test_tampered_written_at_fails(self) -> None:
        from audit.hasher import verify_audit_record_integrity
        agent_hash, record_hmac = self._compute_valid_fields()
        wrong_time = SAMPLE_WRITTEN_AT + timedelta(seconds=1)
        is_valid, reason = verify_audit_record_integrity(
            stored_agent_outputs_hash=agent_hash,
            stored_record_hmac=record_hmac,
            agent_outputs=SAMPLE_AGENT_OUTPUTS,
            decision_id=SAMPLE_DECISION_ID,
            guideline_version_id=SAMPLE_GUIDELINE_VERSION_ID,
            written_at=wrong_time,
        )
        assert is_valid is False

    def test_tampered_stored_hash_fails(self) -> None:
        from audit.hasher import verify_audit_record_integrity
        _, record_hmac = self._compute_valid_fields()
        is_valid, reason = verify_audit_record_integrity(
            stored_agent_outputs_hash="a" * 64,  # Fake hash
            stored_record_hmac=record_hmac,
            agent_outputs=SAMPLE_AGENT_OUTPUTS,
            decision_id=SAMPLE_DECISION_ID,
            guideline_version_id=SAMPLE_GUIDELINE_VERSION_ID,
            written_at=SAMPLE_WRITTEN_AT,
        )
        assert is_valid is False


# ── _serialise_written_at() ───────────────────────────────────────────────────

class TestSerialiseWrittenAt:

    def test_aware_datetime_includes_offset(self) -> None:
        from audit.hasher import _serialise_written_at
        dt = datetime(2026, 6, 1, 12, 0, 0, 0, tzinfo=timezone.utc)
        result = _serialise_written_at(dt)
        assert "+00:00" in result

    def test_naive_datetime_treated_as_utc(self) -> None:
        from audit.hasher import _serialise_written_at
        naive = datetime(2026, 6, 1, 12, 0, 0, 0)
        result = _serialise_written_at(naive)
        assert "+00:00" in result

    def test_consistent_format(self) -> None:
        """Same datetime always produces same string."""
        from audit.hasher import _serialise_written_at
        dt = datetime(2026, 6, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
        r1 = _serialise_written_at(dt)
        r2 = _serialise_written_at(dt)
        assert r1 == r2

    def test_microseconds_included(self) -> None:
        from audit.hasher import _serialise_written_at
        dt = datetime(2026, 6, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
        result = _serialise_written_at(dt)
        assert "123456" in result