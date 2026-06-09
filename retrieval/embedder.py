"""
ComplianceLoop — Sentence Transformer Embedder
================================================
Wraps the sentence-transformers library to produce dense vector embeddings
for regulatory text. Used by both the FAISS index builder and the RAG agent
at query time.

Model: all-MiniLM-L6-v2
  - 384-dimensional output vectors
  - CPU-runnable (no GPU required)
  - 22MB model size
  - Good semantic recall for regulatory/legal text
  - Fast: ~50ms per batch of 32 sentences on CPU

Design decisions:
  - Model is loaded ONCE as a module-level singleton (lazy on first use)
  - Reloading the model (380MB+ total with deps) on every call would be
    prohibitively slow
  - The singleton is process-scoped — each Celery worker process loads
    its own copy (this is correct behaviour)
  - encode() normalises vectors by default (L2 norm = 1.0) so cosine
    similarity equals dot product — FAISS IndexFlatIP is equivalent to
    cosine search on normalised vectors

Thread safety:
  sentence-transformers encode() is thread-safe for read-only inference.
  The model weights are loaded once and never mutated.

DPDP note:
  The embedder never receives raw PII. It only embeds regulatory text
  (RBI circulars, DPDP guidance) and application-derived query strings
  that describe compliance findings (e.g. "FOIR threshold exceeded").
  No applicant identifiers or personal data enters the embedding pipeline.
"""

from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING

import numpy as np
import structlog

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

logger = structlog.get_logger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIMENSION = 384       # Fixed for all-MiniLM-L6-v2
DEFAULT_BATCH_SIZE = 32
MAX_SEQUENCE_LENGTH = 512       # Tokens — model's max context window


# ── Model singleton ───────────────────────────────────────────────────────────

_model: SentenceTransformer | None = None
_model_name: str | None = None


def _load_model(model_name: str) -> SentenceTransformer:
    """
    Load the sentence-transformers model into memory.

    Called once per process on first embed() call.
    Subsequent calls return the cached singleton.

    Args:
        model_name: HuggingFace model identifier or local path.

    Returns:
        Loaded SentenceTransformer model.
    """
    try:
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "sentence-transformers is required for the retrieval layer. "
            "Install with: pip install -r requirements/pipeline.txt"
        ) from exc

    device = os.environ.get("EMBEDDING_DEVICE", "cpu")

    logger.info(
        "embedder.model.loading",
        model_name=model_name,
        device=device,
    )
    start = time.monotonic()
    model = SentenceTransformer(model_name, device=device)
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "embedder.model.loaded",
        model_name=model_name,
        device=device,
        duration_ms=duration_ms,
    )
    return model


def get_model() -> SentenceTransformer:
    """
    Return the embedding model singleton, loading it on first call.

    Returns:
        Loaded SentenceTransformer model.
    """
    global _model, _model_name  # noqa: PLW0603
    model_name = os.environ.get("EMBEDDING_MODEL", DEFAULT_MODEL_NAME)

    if _model is None or _model_name != model_name:
        _model = _load_model(model_name)
        _model_name = model_name

    return _model


def invalidate_model_cache() -> None:
    """
    Unload the cached model from memory.

    Called in tests to reset state between test runs, and during
    model upgrades to force a reload.
    """
    global _model, _model_name  # noqa: PLW0603
    _model = None
    _model_name = None


# ── Embedding functions ───────────────────────────────────────────────────────

def embed(text: str, normalise: bool = True) -> np.ndarray:
    """
    Embed a single text string into a dense vector.

    Args:
        text: Input text to embed. Should be under 512 tokens (~380 words).
              Longer texts are silently truncated by the model.
        normalise: If True (default), L2-normalise the output vector so
                   cosine similarity equals dot product. Required for FAISS
                   IndexFlatIP compatibility.

    Returns:
        1D numpy array of shape (384,) with dtype float32.

    Raises:
        ValueError: If text is empty.
        ImportError: If sentence-transformers is not installed.
    """
    if not text or not text.strip():
        raise ValueError("Cannot embed empty text.")

    model = get_model()
    vector = model.encode(
        text,
        normalize_embeddings=normalise,
        show_progress_bar=False,
        convert_to_numpy=True,
    )
    return vector.astype(np.float32)


def batch_embed(
    texts: list[str],
    batch_size: int | None = None,
    normalise: bool = True,
    show_progress: bool = False,
) -> np.ndarray:
    """
    Embed a list of texts in batches.

    Used during FAISS index construction to embed large regulatory corpora
    efficiently. Processes texts in batches to manage memory usage.

    Args:
        texts: List of text strings to embed. Empty strings are filtered out.
        batch_size: Number of texts per encoding batch.
                    Defaults to EMBEDDING_BATCH_SIZE env var (default 32).
        normalise: If True (default), L2-normalise all output vectors.
        show_progress: If True, display a tqdm progress bar. Useful during
                       index construction but should be False in production.

    Returns:
        2D numpy array of shape (len(texts), 384) with dtype float32.
        Rows correspond to input texts in order (empty texts are embedded
        as zero vectors — they should not appear in practice).

    Raises:
        ValueError: If texts list is empty.
        ImportError: If sentence-transformers is not installed.
    """
    if not texts:
        raise ValueError("Cannot embed empty text list.")

    effective_batch_size = batch_size or int(
        os.environ.get("EMBEDDING_BATCH_SIZE", str(DEFAULT_BATCH_SIZE))
    )

    # Filter empty texts but track positions for zero-padding
    non_empty = [(i, t) for i, t in enumerate(texts) if t and t.strip()]
    if not non_empty:
        raise ValueError("All texts in the list are empty.")

    model = get_model()
    indices, clean_texts = zip(*non_empty)

    start = time.monotonic()
    vectors = model.encode(
        list(clean_texts),
        batch_size=effective_batch_size,
        normalize_embeddings=normalise,
        show_progress_bar=show_progress,
        convert_to_numpy=True,
    )
    duration_ms = int((time.monotonic() - start) * 1000)

    # Reconstruct full array with zero vectors for any empty-text positions
    if len(non_empty) < len(texts):
        dim = vectors.shape[1] if len(vectors.shape) > 1 else EMBEDDING_DIMENSION
        result = np.zeros((len(texts), dim), dtype=np.float32)
        for result_idx, (orig_idx, _) in enumerate(non_empty):
            result[orig_idx] = vectors[result_idx]
        vectors = result

    logger.debug(
        "embedder.batch.completed",
        text_count=len(texts),
        batch_size=effective_batch_size,
        duration_ms=duration_ms,
        vectors_per_second=round(len(texts) / max(duration_ms / 1000, 0.001), 1),
    )

    return vectors.astype(np.float32)


def get_embedding_dimension() -> int:
    """
    Return the embedding dimension for the current model.

    Used by FAISS index builder to configure the index dimension.
    Also readable from FAISS_INDEX_DIMENSION env var as a faster
    alternative that avoids loading the model just to get the dimension.

    Returns:
        Integer embedding dimension (384 for all-MiniLM-L6-v2).
    """
    env_dim = os.environ.get("FAISS_INDEX_DIMENSION")
    if env_dim:
        return int(env_dim)
    return EMBEDDING_DIMENSION


def compute_similarity(vec_a: np.ndarray, vec_b: np.ndarray) -> float:
    """
    Compute cosine similarity between two normalised embedding vectors.

    Since both vectors are L2-normalised (normalise=True default),
    cosine similarity equals the dot product.

    Args:
        vec_a: First normalised embedding vector, shape (384,).
        vec_b: Second normalised embedding vector, shape (384,).

    Returns:
        Float similarity score in range [-1.0, 1.0].
        1.0 = identical, 0.0 = orthogonal, -1.0 = opposite.
    """
    return float(np.dot(vec_a, vec_b))