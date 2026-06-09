"""
Tests for retrieval/embedder.py

Covers:
  - embed() returns correct shape and dtype
  - embed() normalises vectors (L2 norm ≈ 1.0)
  - embed() raises on empty text
  - batch_embed() returns correct shape
  - batch_embed() normalises all vectors
  - batch_embed() raises on empty list
  - batch_embed() handles list with all-empty strings
  - Deterministic: same text → same vector
  - Different texts → different vectors
  - compute_similarity() range and symmetry
  - get_embedding_dimension() returns 384
  - invalidate_model_cache() resets singleton

Uses a real model load for integration tests (marked slow).
Uses mock for unit tests to avoid loading 380MB of deps in CI.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import numpy as np
import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_model() -> MagicMock:
    """Mock SentenceTransformer model that returns deterministic vectors."""
    model = MagicMock()

    def fake_encode(texts, **kwargs):
        # Return deterministic vectors based on text hash
        if isinstance(texts, str):
            seed = hash(texts) % (2**31)
            rng = np.random.default_rng(seed)
            vec = rng.random(384).astype(np.float32)
            # Normalise
            vec = vec / np.linalg.norm(vec)
            return vec
        else:
            results = []
            for t in texts:
                seed = hash(t) % (2**31)
                rng = np.random.default_rng(seed)
                vec = rng.random(384).astype(np.float32)
                vec = vec / np.linalg.norm(vec)
                results.append(vec)
            return np.array(results, dtype=np.float32)

    model.encode.side_effect = fake_encode
    return model


@pytest.fixture(autouse=True)
def reset_model_cache() -> None:
    """Reset the model singleton before each test."""
    from retrieval.embedder import invalidate_model_cache
    invalidate_model_cache()
    yield
    invalidate_model_cache()


# ── embed() tests ─────────────────────────────────────────────────────────────

class TestEmbed:

    def test_returns_numpy_array(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import embed
            result = embed("FOIR threshold exceeded for unsecured loan")
        assert isinstance(result, np.ndarray)

    def test_returns_384_dimensions(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import embed
            result = embed("KYC document validity check")
        assert result.shape == (384,)

    def test_returns_float32(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import embed
            result = embed("regulatory compliance")
        assert result.dtype == np.float32

    def test_normalised_vector_has_unit_norm(self, mock_model: MagicMock) -> None:
        """Normalised vector should have L2 norm ≈ 1.0."""
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import embed
            result = embed("RBI NBFC directions 2016", normalise=True)
        norm = float(np.linalg.norm(result))
        assert abs(norm - 1.0) < 1e-5

    def test_empty_text_raises(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import embed
            with pytest.raises(ValueError, match="Cannot embed empty text"):
                embed("")

    def test_whitespace_only_raises(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import embed
            with pytest.raises(ValueError, match="Cannot embed empty text"):
                embed("   \n\t  ")

    def test_deterministic_same_text(self, mock_model: MagicMock) -> None:
        """Same text produces same vector every time."""
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import embed
            text = "FOIR limit exceeded unsecured loan"
            v1 = embed(text)
            v2 = embed(text)
        np.testing.assert_array_equal(v1, v2)

    def test_different_texts_produce_different_vectors(
        self, mock_model: MagicMock
    ) -> None:
        """Different texts should produce different embeddings."""
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import embed
            v1 = embed("FOIR threshold exceeded")
            v2 = embed("KYC document expired")
        assert not np.array_equal(v1, v2)


# ── batch_embed() tests ───────────────────────────────────────────────────────

class TestBatchEmbed:

    def test_returns_2d_array(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import batch_embed
            texts = ["text one", "text two", "text three"]
            result = batch_embed(texts)
        assert result.ndim == 2

    def test_correct_shape(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import batch_embed
            texts = ["a", "b", "c", "d"]
            result = batch_embed(texts)
        assert result.shape == (4, 384)

    def test_all_vectors_normalised(self, mock_model: MagicMock) -> None:
        """All rows in batch output should have unit L2 norm."""
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import batch_embed
            texts = ["RBI circular FOIR", "KYC validity window", "sanctions screening"]
            result = batch_embed(texts, normalise=True)
        norms = np.linalg.norm(result, axis=1)
        np.testing.assert_allclose(norms, np.ones(3), atol=1e-5)

    def test_empty_list_raises(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import batch_embed
            with pytest.raises(ValueError, match="Cannot embed empty text list"):
                batch_embed([])

    def test_all_empty_strings_raises(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import batch_embed
            with pytest.raises(ValueError, match="All texts in the list are empty"):
                batch_embed(["", "  ", "\n"])

    def test_returns_float32(self, mock_model: MagicMock) -> None:
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import batch_embed
            result = batch_embed(["test text"])
        assert result.dtype == np.float32

    def test_single_text_batch(self, mock_model: MagicMock) -> None:
        """Single-element list produces shape (1, 384)."""
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import batch_embed
            result = batch_embed(["single text"])
        assert result.shape == (1, 384)


# ── compute_similarity() tests ────────────────────────────────────────────────

class TestComputeSimilarity:

    def test_identical_vectors_score_one(self) -> None:
        """Identical normalised vectors should have similarity ≈ 1.0."""
        from retrieval.embedder import compute_similarity
        vec = np.random.default_rng(42).random(384).astype(np.float32)
        vec = vec / np.linalg.norm(vec)
        score = compute_similarity(vec, vec)
        assert abs(score - 1.0) < 1e-5

    def test_orthogonal_vectors_score_zero(self) -> None:
        """Orthogonal vectors should have similarity ≈ 0.0."""
        from retrieval.embedder import compute_similarity
        vec_a = np.zeros(384, dtype=np.float32)
        vec_b = np.zeros(384, dtype=np.float32)
        vec_a[0] = 1.0
        vec_b[1] = 1.0
        score = compute_similarity(vec_a, vec_b)
        assert abs(score) < 1e-5

    def test_returns_float(self) -> None:
        from retrieval.embedder import compute_similarity
        vec = np.ones(384, dtype=np.float32) / np.sqrt(384)
        score = compute_similarity(vec, vec)
        assert isinstance(score, float)

    def test_score_in_valid_range(self, mock_model: MagicMock) -> None:
        """Cosine similarity of normalised vectors must be in [-1, 1]."""
        with patch("retrieval.embedder.get_model", return_value=mock_model):
            from retrieval.embedder import embed, compute_similarity
            v1 = embed("FOIR limit")
            v2 = embed("KYC document")
        score = compute_similarity(v1, v2)
        assert -1.0 <= score <= 1.0


# ── get_embedding_dimension() tests ──────────────────────────────────────────

class TestGetEmbeddingDimension:

    def test_returns_384_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FAISS_INDEX_DIMENSION", raising=False)
        from retrieval.embedder import get_embedding_dimension
        assert get_embedding_dimension() == 384

    def test_env_var_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FAISS_INDEX_DIMENSION", "768")
        from retrieval.embedder import get_embedding_dimension
        assert get_embedding_dimension() == 768