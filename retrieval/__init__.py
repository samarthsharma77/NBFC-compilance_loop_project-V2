"""
ComplianceLoop — Retrieval Module
===================================
FAISS-based retrieval layer for regulatory corpus search.

Components:
  - embedder       : sentence-transformers all-MiniLM-L6-v2 wrapper
  - chunker        : sliding-window text chunker with overlap
  - corpus/        : PDF and HTML extractors + preprocessor
  - index_manager  : FAISS index build, health check, safe atomic swap
  - retriever      : query interface for RAG agent

Usage (RAG agent):
    from retrieval import IndexManager, FAISSRetriever

    # Load index (called once at worker startup)
    manager = IndexManager()
    manager.load()

    # Query (called per pipeline run)
    retriever = FAISSRetriever(index_manager=manager)
    results = retriever.query_with_context(
        agent_findings=[{"finding_code": "FOIR_THRESHOLD_EXCEEDED", "severity": "FAIL", ...}],
        loan_purpose="PERSONAL_UNSECURED",
        top_k=5,
    )

Usage (index builder — scraper/tasks.py):
    from retrieval import IndexManager
    from retrieval.chunker import chunk_text
    from retrieval.corpus import extract_text_from_pdf, preprocess

    text = extract_text_from_pdf(pdf_bytes)
    doc = preprocess(text, source_document_id="RBI/2024-25/73...", source_url=url)
    chunks = chunk_text(doc.text, doc.source_document_id, doc.source_url)

    manager = IndexManager()
    manager.build(chunks)
    manager.safe_swap()
"""

from retrieval.embedder import (
    batch_embed,
    compute_similarity,
    embed,
    get_embedding_dimension,
    get_model,
    invalidate_model_cache,
)
from retrieval.chunker import (
    TextChunk,
    chunk_text,
    count_tokens,
)
from retrieval.index_manager import IndexManager
from retrieval.retriever import FAISSRetriever, RetrievedChunk

__all__ = [
    # Embedder
    "embed",
    "batch_embed",
    "get_model",
    "get_embedding_dimension",
    "compute_similarity",
    "invalidate_model_cache",
    # Chunker
    "TextChunk",
    "chunk_text",
    "count_tokens",
    # Index
    "IndexManager",
    # Retriever
    "FAISSRetriever",
    "RetrievedChunk",
]