"""
ComplianceLoop — FAISS Retriever
==================================
Provides the query interface over the FAISS index for the RAG agent.

The retriever takes a natural-language query string, embeds it using
the same model that built the index, and returns the top-k most
similar chunks with their metadata.

Query flow:
  1. Embed the query string → 384-dim vector (normalised)
  2. Search FAISS IndexFlatIP → top-k (faiss_ids, distances)
  3. Look up chunk metadata in id_map for each faiss_id
  4. Return list of RetrievedChunk objects with text + metadata + score

The retriever is stateless w.r.t. the index — it holds a reference to
the IndexManager which manages the actual FAISS index object. When the
IndexManager reloads the index (after a safe swap), the retriever
automatically uses the new index on the next query.

DPDP note:
  Queries constructed by the RAG agent describe compliance findings
  (e.g. "FOIR threshold exceeded for unsecured loan") — they do NOT
  contain personal data. The query construction logic in the RAG agent
  strips any applicant identifiers before constructing the query string.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import numpy as np
import structlog

logger = structlog.get_logger(__name__)


# ── Result data class ─────────────────────────────────────────────────────────

@dataclass
class RetrievedChunk:
    """A single retrieval result from the FAISS index."""

    text: str                       # The chunk text
    score: float                    # Cosine similarity score (0.0–1.0)
    source_document_id: str         # Circular reference
    source_url: str                 # Original URL of the circular
    section_hint: str               # Nearest section heading
    chunk_index: int                # Position in original document
    token_count: int                # Approximate token count
    faiss_id: int                   # Raw FAISS integer ID (for debugging)

    def to_citation(self) -> str:
        """
        Format a short citation string for the RAG agent's response.

        Returns:
            E.g. "RBI/2024-25/73 DNBR.CC.PD.No.141 — Section 4.2"
        """
        return f"{self.source_document_id} — {self.section_hint}"

    def to_dict(self) -> dict[str, Any]:
        """Serialise to dict for logging and API response."""
        return {
            "text": self.text[:200] + "..." if len(self.text) > 200 else self.text,
            "score": round(self.score, 4),
            "source_document_id": self.source_document_id,
            "source_url": self.source_url,
            "section_hint": self.section_hint,
            "chunk_index": self.chunk_index,
            "token_count": self.token_count,
        }


# ── Retriever ─────────────────────────────────────────────────────────────────

class FAISSRetriever:
    """
    Retriever over the FAISS index for compliance RAG queries.

    One instance per RAG agent worker. Holds a reference to the shared
    IndexManager so index reloads are reflected automatically.
    """

    def __init__(
        self,
        index_manager: Any,     # IndexManager — typed as Any to avoid circular import
        min_score_threshold: float = 0.0,
    ) -> None:
        """
        Args:
            index_manager: IndexManager instance with a loaded index.
            min_score_threshold: Minimum cosine similarity score to include
                                 in results. 0.0 means return all top-k.
                                 Raise to ~0.3 to filter low-relevance results.
        """
        self._manager = index_manager
        self.min_score_threshold = min_score_threshold

    def query(
        self,
        query_text: str,
        top_k: int = 5,
    ) -> list[RetrievedChunk]:
        """
        Retrieve the top-k most relevant chunks for a query.

        Args:
            query_text: Natural language query string.
                        Should describe the compliance context, not the applicant.
                        E.g. "FOIR limit for unsecured personal loans NBFC"
            top_k: Number of results to return. Default 5 (RAG agent uses top-5).

        Returns:
            List of RetrievedChunk objects sorted by descending score.
            May be shorter than top_k if fewer results pass min_score_threshold.

        Raises:
            RuntimeError: If index is not loaded.
            ValueError: If query_text is empty.
        """
        if not query_text or not query_text.strip():
            raise ValueError("Query text cannot be empty.")

        if not self._manager.is_loaded():
            raise RuntimeError(
                "FAISS index is not loaded. "
                "Call IndexManager.load() before querying."
            )

        from retrieval.embedder import embed  # noqa: PLC0415
        from observability.metrics import RAG_RETRIEVAL_DURATION  # noqa: PLC0415

        start = time.monotonic()

        try:
            # Embed query
            query_vector = embed(query_text, normalise=True)
            query_matrix = query_vector.reshape(1, -1)   # FAISS expects 2D array

            # Search
            index = self._manager._index
            id_map = self._manager._id_map

            distances, faiss_ids = index.search(query_matrix, top_k)

            # Build results
            results: list[RetrievedChunk] = []
            for score, fid in zip(distances[0], faiss_ids[0]):
                if fid == -1:
                    # FAISS returns -1 for padding when fewer results available
                    continue
                score_float = float(score)
                if score_float < self.min_score_threshold:
                    continue

                metadata = id_map.get(int(fid), {})
                chunk = RetrievedChunk(
                    text=metadata.get("text", ""),
                    score=score_float,
                    source_document_id=metadata.get("source_document_id", "unknown"),
                    source_url=metadata.get("source_url", ""),
                    section_hint=metadata.get("section_hint", ""),
                    chunk_index=int(metadata.get("chunk_index", 0)),
                    token_count=int(metadata.get("token_count", 0)),
                    faiss_id=int(fid),
                )
                results.append(chunk)

            duration_ms = int((time.monotonic() - start) * 1000)

            RAG_RETRIEVAL_DURATION.labels(
                status="success",
                is_demo="false",
            ).observe(duration_ms)

            logger.debug(
                "retriever.query.completed",
                query_preview=query_text[:80],
                results_count=len(results),
                top_score=round(results[0].score, 4) if results else 0.0,
                duration_ms=duration_ms,
            )

            return results

        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            RAG_RETRIEVAL_DURATION.labels(
                status="error",
                is_demo="false",
            ).observe(duration_ms)
            logger.error(
                "retriever.query.failed",
                query_preview=query_text[:80],
                error=str(exc),
                duration_ms=duration_ms,
            )
            raise

    def query_with_context(
        self,
        agent_findings: list[dict[str, Any]],
        loan_purpose: str,
        top_k: int = 5,
    ) -> list[RetrievedChunk]:
        """
        Build a query from agent findings and retrieve relevant chunks.

        This is the primary entry point for the RAG agent. It constructs
        a query string from the structured agent findings and loan purpose,
        rather than requiring the RAG agent to construct the query manually.

        Args:
            agent_findings: List of finding dicts from the other four agents.
                            Each dict has: {agent_name, finding_code, severity, message}
            loan_purpose: Loan purpose taxonomy code (e.g. PERSONAL_UNSECURED).
            top_k: Number of results to return.

        Returns:
            List of RetrievedChunk objects.
        """
        query = _build_query_from_findings(agent_findings, loan_purpose)
        return self.query(query, top_k=top_k)


def _build_query_from_findings(
    findings: list[dict[str, Any]],
    loan_purpose: str,
) -> str:
    """
    Construct a retrieval query from agent findings.

    The query is designed to retrieve RBI circular passages that are
    most relevant to the specific compliance issues found.

    Args:
        findings: Agent finding dicts with keys: agent_name, finding_code,
                  severity, message.
        loan_purpose: Loan purpose code.

    Returns:
        Query string for FAISS retrieval.
    """
    # Expand loan purpose to human-readable
    purpose_map = {
        "PERSONAL_UNSECURED": "unsecured personal loan",
        "HOME_SECURED": "housing loan secured",
        "VEHICLE_SECURED": "vehicle loan secured",
        "BUSINESS_UNSECURED": "business loan unsecured",
        "MICROFINANCE": "microfinance loan",
    }
    purpose_text = purpose_map.get(loan_purpose, loan_purpose.lower().replace("_", " "))

    # Build query from FAIL and WARN findings
    relevant_findings = [
        f for f in findings
        if f.get("severity") in ("FAIL", "WARN")
    ]

    if not relevant_findings:
        # No issues found — retrieve general NBFC compliance requirements
        return (
            f"RBI NBFC {purpose_text} compliance requirements "
            "KYC documentation income proof approval criteria"
        )

    # Extract key concepts from finding codes
    finding_concepts = []
    for finding in relevant_findings[:3]:  # Limit to top 3 findings
        code = finding.get("finding_code", "")
        message = finding.get("message", "")

        if "FOIR" in code or "FOIR" in message:
            finding_concepts.append("FOIR fixed obligation income ratio limit")
        elif "KYC" in code or "DOCUMENT" in code:
            finding_concepts.append("KYC documentation requirements OVD validity")
        elif "SANCTIONS" in code or "WATCHLIST" in code:
            finding_concepts.append("sanctions screening watchlist PMLA requirements")
        elif "TEMPORAL" in code or "EXPIRY" in code:
            finding_concepts.append("KYC validity period update interval requirements")
        elif "LTV" in code:
            finding_concepts.append("loan to value ratio secured loans")
        elif "NTH" in code:
            finding_concepts.append("net take home income repayment capacity")
        else:
            # Use message text directly as it describes the issue
            finding_concepts.append(message[:100] if message else code)

    concepts_text = ". ".join(finding_concepts)
    query = (
        f"RBI NBFC {purpose_text} regulations: {concepts_text}. "
        "What do the RBI guidelines require?"
    )

    return query