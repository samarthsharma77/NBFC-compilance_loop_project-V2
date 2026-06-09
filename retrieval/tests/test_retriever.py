"""
Tests for retrieval/retriever.py

Covers:
  - FAISSRetriever.query() raises on empty query
  - FAISSRetriever.query() raises RuntimeError when index not loaded
  - FAISSRetriever.query() returns list of RetrievedChunk
  - FAISSRetriever.query() respects top_k parameter
  - FAISSRetriever.query() filters by min_score_threshold
  - FAISSRetriever.query() handles FAISS -1 padding IDs
  - RetrievedChunk.to_citation() format
  - RetrievedChunk.to_dict() truncates long text
  - _build_query_from_findings() constructs relevant queries
  - query_with_context() delegates to query() correctly
  - Prometheus metric is recorded on success and error
"""

from __future__ import annotations

import numpy as np
import pytest
from unittest.mock import MagicMock, patch

from retrieval.retriever import (
    FAISSRetriever,
    RetrievedChunk,
    _build_query_from_findings,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_index_manager() -> MagicMock:
    """Mock IndexManager with a loaded FAISS index and id_map."""
    manager = MagicMock()
    manager.is_loaded.return_value = True

    # Mock FAISS index
    mock_index = MagicMock()
    # search returns distances and IDs for top-3
    mock_index.search.return_value = (
        np.array([[0.95, 0.80, 0.65]], dtype=np.float32),
        np.array([[0, 1, 2]], dtype=np.int64),
    )
    manager._index = mock_index

    # Mock id_map
    manager._id_map = {
        0: {
            "text": "FOIR shall not exceed fifty percent for unsecured loans.",
            "chunk_index": 0,
            "source_document_id": "RBI_NBFC_DIRECTIONS_2016",
            "source_url": "https://rbi.org.in/circular1",
            "section_hint": "Section 4.2",
            "char_start": 0,
            "char_end": 55,
            "token_count": 10,
        },
        1: {
            "text": "KYC documents must include an Officially Valid Document.",
            "chunk_index": 1,
            "source_document_id": "RBI_KYC_MASTER_DIRECTION_2016",
            "source_url": "https://rbi.org.in/circular2",
            "section_hint": "Section 3.1",
            "char_start": 0,
            "char_end": 55,
            "token_count": 9,
        },
        2: {
            "text": "Sanctions screening is mandatory for all NBFC loan applicants.",
            "chunk_index": 2,
            "source_document_id": "RBI_KYC_MASTER_DIRECTION_2016",
            "source_url": "https://rbi.org.in/circular2",
            "section_hint": "Section 5.3",
            "char_start": 0,
            "char_end": 62,
            "token_count": 11,
        },
    }

    return manager


@pytest.fixture
def retriever(mock_index_manager: MagicMock) -> FAISSRetriever:
    return FAISSRetriever(index_manager=mock_index_manager)


@pytest.fixture
def mock_embed_fn() -> MagicMock:
    """Mock embed() that returns a normalised 384-dim vector."""
    def _embed(text: str, normalise: bool = True) -> np.ndarray:
        rng = np.random.default_rng(hash(text) % (2**31))
        vec = rng.random(384).astype(np.float32)
        return vec / np.linalg.norm(vec)
    return MagicMock(side_effect=_embed)


# ── query() basic tests ────────────────────────────────────────────────────────

class TestQuery:

    def test_raises_on_empty_query(self, retriever: FAISSRetriever) -> None:
        with pytest.raises(ValueError, match="Query text cannot be empty"):
            with patch("retrieval.retriever.embed"):
                retriever.query("")

    def test_raises_on_whitespace_query(self, retriever: FAISSRetriever) -> None:
        with pytest.raises(ValueError, match="Query text cannot be empty"):
            with patch("retrieval.retriever.embed"):
                retriever.query("   \n  ")

    def test_raises_when_index_not_loaded(
        self, mock_index_manager: MagicMock
    ) -> None:
        mock_index_manager.is_loaded.return_value = False
        retriever = FAISSRetriever(index_manager=mock_index_manager)
        with pytest.raises(RuntimeError, match="FAISS index is not loaded"):
            with patch("retrieval.retriever.embed"):
                retriever.query("FOIR limit")

    def test_returns_list_of_retrieved_chunks(
        self, retriever: FAISSRetriever, mock_embed_fn: MagicMock
    ) -> None:
        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION"):
            results = retriever.query("FOIR threshold NBFC unsecured loan")

        assert isinstance(results, list)
        assert all(isinstance(r, RetrievedChunk) for r in results)

    def test_returns_top_k_results(
        self, retriever: FAISSRetriever, mock_embed_fn: MagicMock
    ) -> None:
        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION"):
            results = retriever.query("FOIR", top_k=2)

        # FAISS mock returns 3 results but we ask for top_k=2
        # The mock index.search is called with k=2 — verify
        retriever._manager._index.search.assert_called_once()
        call_args = retriever._manager._index.search.call_args
        assert call_args[0][1] == 2  # k argument

    def test_results_have_correct_scores(
        self, retriever: FAISSRetriever, mock_embed_fn: MagicMock
    ) -> None:
        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION"):
            results = retriever.query("FOIR")

        # Scores come from mock: [0.95, 0.80, 0.65]
        scores = [r.score for r in results]
        assert scores[0] == pytest.approx(0.95, abs=0.01)
        assert scores[1] == pytest.approx(0.80, abs=0.01)
        assert scores[2] == pytest.approx(0.65, abs=0.01)

    def test_results_sorted_by_descending_score(
        self, retriever: FAISSRetriever, mock_embed_fn: MagicMock
    ) -> None:
        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION"):
            results = retriever.query("compliance")

        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_results_have_metadata(
        self, retriever: FAISSRetriever, mock_embed_fn: MagicMock
    ) -> None:
        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION"):
            results = retriever.query("KYC requirements")

        first = results[0]
        assert first.source_document_id == "RBI_NBFC_DIRECTIONS_2016"
        assert first.source_url.startswith("https://")
        assert first.section_hint != ""
        assert first.text != ""
        assert first.chunk_index >= 0

    def test_filters_by_min_score_threshold(
        self, mock_index_manager: MagicMock, mock_embed_fn: MagicMock
    ) -> None:
        """Results below min_score_threshold are excluded."""
        retriever = FAISSRetriever(
            index_manager=mock_index_manager,
            min_score_threshold=0.85,   # Only score 0.95 should pass
        )
        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION"):
            results = retriever.query("FOIR")

        # Only score 0.95 passes threshold 0.85
        assert len(results) == 1
        assert results[0].score == pytest.approx(0.95, abs=0.01)

    def test_handles_faiss_padding_ids(
        self, mock_index_manager: MagicMock, mock_embed_fn: MagicMock
    ) -> None:
        """FAISS returns -1 for padding when fewer results than top_k."""
        mock_index_manager._index.search.return_value = (
            np.array([[0.90, 0.0, 0.0]], dtype=np.float32),
            np.array([[0, -1, -1]], dtype=np.int64),  # 2 padding IDs
        )
        retriever = FAISSRetriever(index_manager=mock_index_manager)
        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION"):
            results = retriever.query("test")

        # Only 1 real result (id=0), -1 padding ignored
        assert len(results) == 1

    def test_records_prometheus_metric_on_success(
        self, retriever: FAISSRetriever, mock_embed_fn: MagicMock
    ) -> None:
        mock_metric = MagicMock()
        mock_histogram = MagicMock()
        mock_metric.labels.return_value = mock_histogram

        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION", mock_metric):
            retriever.query("FOIR")

        mock_metric.labels.assert_called_with(status="success", is_demo="false")
        mock_histogram.observe.assert_called_once()

    def test_records_prometheus_metric_on_error(
        self, retriever: FAISSRetriever
    ) -> None:
        mock_metric = MagicMock()
        mock_histogram = MagicMock()
        mock_metric.labels.return_value = mock_histogram

        def bad_embed(text, normalise=True):
            raise RuntimeError("embedding failed")

        with patch("retrieval.retriever.embed", side_effect=bad_embed), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION", mock_metric), \
             pytest.raises(RuntimeError):
            retriever.query("FOIR")

        mock_metric.labels.assert_called_with(status="error", is_demo="false")


# ── RetrievedChunk tests ──────────────────────────────────────────────────────

class TestRetrievedChunk:

    def test_to_citation_format(self) -> None:
        chunk = RetrievedChunk(
            text="Some regulatory text.",
            score=0.92,
            source_document_id="RBI_NBFC_DIRECTIONS_2016",
            source_url="https://rbi.org.in",
            section_hint="Section 4.2",
            chunk_index=0,
            token_count=5,
            faiss_id=0,
        )
        citation = chunk.to_citation()
        assert "RBI_NBFC_DIRECTIONS_2016" in citation
        assert "Section 4.2" in citation
        assert " — " in citation

    def test_to_dict_truncates_long_text(self) -> None:
        long_text = "a" * 500
        chunk = RetrievedChunk(
            text=long_text,
            score=0.8,
            source_document_id="doc",
            source_url="https://example.com",
            section_hint="intro",
            chunk_index=0,
            token_count=100,
            faiss_id=0,
        )
        d = chunk.to_dict()
        assert len(d["text"]) <= 203 + 3  # 200 chars + "..."

    def test_to_dict_short_text_not_truncated(self) -> None:
        short_text = "Short text."
        chunk = RetrievedChunk(
            text=short_text,
            score=0.9,
            source_document_id="doc",
            source_url="https://example.com",
            section_hint="intro",
            chunk_index=0,
            token_count=3,
            faiss_id=0,
        )
        d = chunk.to_dict()
        assert d["text"] == short_text

    def test_to_dict_has_required_keys(self) -> None:
        chunk = RetrievedChunk(
            text="text",
            score=0.7,
            source_document_id="doc",
            source_url="url",
            section_hint="hint",
            chunk_index=1,
            token_count=2,
            faiss_id=5,
        )
        d = chunk.to_dict()
        required = {"text", "score", "source_document_id", "source_url",
                    "section_hint", "chunk_index", "token_count"}
        assert required.issubset(set(d.keys()))

    def test_score_rounded_in_dict(self) -> None:
        chunk = RetrievedChunk(
            text="t", score=0.123456789,
            source_document_id="d", source_url="u",
            section_hint="s", chunk_index=0,
            token_count=1, faiss_id=0,
        )
        d = chunk.to_dict()
        assert d["score"] == round(0.123456789, 4)


# ── _build_query_from_findings() tests ────────────────────────────────────────

class TestBuildQueryFromFindings:

    def test_no_findings_returns_general_query(self) -> None:
        query = _build_query_from_findings([], "PERSONAL_UNSECURED")
        assert "unsecured personal loan" in query.lower()
        assert "RBI" in query
        assert "NBFC" in query

    def test_foir_finding_produces_foir_query(self) -> None:
        findings = [
            {
                "agent_name": "transaction",
                "finding_code": "FOIR_THRESHOLD_EXCEEDED",
                "severity": "FAIL",
                "message": "FOIR exceeds 50% limit",
            }
        ]
        query = _build_query_from_findings(findings, "PERSONAL_UNSECURED")
        assert "FOIR" in query or "fixed obligation" in query.lower()

    def test_kyc_finding_produces_kyc_query(self) -> None:
        findings = [
            {
                "agent_name": "document",
                "finding_code": "DOC_KYC_EXPIRED",
                "severity": "FAIL",
                "message": "KYC document has expired",
            }
        ]
        query = _build_query_from_findings(findings, "HOME_SECURED")
        assert "KYC" in query or "document" in query.lower()

    def test_sanctions_finding_produces_sanctions_query(self) -> None:
        findings = [
            {
                "agent_name": "sanctions",
                "finding_code": "SANCTIONS_NAME_MATCH",
                "severity": "WARN",
                "message": "Name fuzzy match on watchlist",
            }
        ]
        query = _build_query_from_findings(findings, "PERSONAL_UNSECURED")
        assert "sanctions" in query.lower() or "watchlist" in query.lower() or "PMLA" in query

    def test_pass_findings_ignored_in_query(self) -> None:
        """PASS findings should not contribute to the query."""
        findings = [
            {
                "agent_name": "document",
                "finding_code": "DOC_PAN_PRESENT",
                "severity": "PASS",
                "message": "PAN is present",
            }
        ]
        # Only PASS findings — should use general query
        query = _build_query_from_findings(findings, "PERSONAL_UNSECURED")
        # General query should mention compliance or NBFC
        assert "NBFC" in query or "compliance" in query.lower()

    def test_loan_purpose_in_query(self) -> None:
        query = _build_query_from_findings([], "HOME_SECURED")
        assert "housing" in query.lower() or "secured" in query.lower()

    def test_limits_to_top_3_findings(self) -> None:
        """Only top 3 FAIL/WARN findings should be included."""
        findings = [
            {
                "agent_name": f"agent_{i}",
                "finding_code": f"CODE_{i}",
                "severity": "FAIL",
                "message": f"Finding number {i} with detailed message",
            }
            for i in range(10)
        ]
        query = _build_query_from_findings(findings, "PERSONAL_UNSECURED")
        # Query should not be excessively long from 10 findings
        assert len(query) < 2000


# ── query_with_context() tests ────────────────────────────────────────────────

class TestQueryWithContext:

    def test_delegates_to_query(
        self, retriever: FAISSRetriever, mock_embed_fn: MagicMock
    ) -> None:
        findings = [
            {
                "agent_name": "transaction",
                "finding_code": "FOIR_THRESHOLD_EXCEEDED",
                "severity": "FAIL",
                "message": "FOIR exceeds limit",
            }
        ]

        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION"), \
             patch.object(retriever, "query", wraps=retriever.query) as mock_query:
            results = retriever.query_with_context(
                agent_findings=findings,
                loan_purpose="PERSONAL_UNSECURED",
                top_k=3,
            )

        # query() should have been called with top_k=3
        mock_query.assert_called_once()
        call_kwargs = mock_query.call_args[1]
        assert call_kwargs.get("top_k") == 3

    def test_returns_retrieved_chunks(
        self, retriever: FAISSRetriever, mock_embed_fn: MagicMock
    ) -> None:
        with patch("retrieval.retriever.embed", side_effect=mock_embed_fn), \
             patch("retrieval.retriever.RAG_RETRIEVAL_DURATION"):
            results = retriever.query_with_context(
                agent_findings=[],
                loan_purpose="PERSONAL_UNSECURED",
            )

        assert isinstance(results, list)
        assert all(isinstance(r, RetrievedChunk) for r in results)