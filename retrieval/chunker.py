"""
ComplianceLoop — Text Chunker
==============================
Splits regulatory circular text into overlapping chunks suitable for
embedding and FAISS indexing.

Chunking strategy: sliding window with overlap
  - Window size: 512 tokens (~380 words)
  - Overlap: 128 tokens (~96 words)
  - Why overlap? Preserves context across chunk boundaries. A sentence
    that spans two adjacent windows appears in both, ensuring it can
    be retrieved regardless of which chunk is queried.

Token counting:
  Uses tiktoken (cl100k_base encoding — same as GPT-4, close approximation
  for all-MiniLM-L6-v2's WordPiece tokeniser). Exact token counts differ
  slightly but cl100k_base is a good approximation and is fast.

Chunk metadata:
  Each chunk carries its source reference (circular number, section,
  paragraph) for the RAG agent to include in citations. This metadata
  is stored in the FAISS ID map alongside the vector.

RBI circular structure awareness:
  RBI circulars have a predictable structure: preamble, numbered sections,
  subsections, annexures. The chunker respects paragraph boundaries where
  possible — it will not split a sentence across chunks unless the sentence
  itself exceeds the window size.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class TextChunk:
    """A single text chunk with metadata for FAISS indexing."""

    text: str
    chunk_index: int             # Position in the chunk sequence for this document
    source_document_id: str      # Circular reference or document identifier
    source_url: str              # Original URL of the circular
    section_hint: str            # Nearest section heading (best-effort extraction)
    char_start: int              # Character offset in original text
    char_end: int                # Character offset in original text
    token_count: int             # Approximate token count for this chunk

    def to_metadata_dict(self) -> dict[str, str | int]:
        """Serialise metadata for storage in FAISS ID map."""
        return {
            "chunk_index": self.chunk_index,
            "source_document_id": self.source_document_id,
            "source_url": self.source_url,
            "section_hint": self.section_hint,
            "char_start": self.char_start,
            "char_end": self.char_end,
            "token_count": self.token_count,
        }


# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_CHUNK_SIZE_TOKENS = 512
DEFAULT_OVERLAP_TOKENS = 128
MIN_CHUNK_SIZE_TOKENS = 50      # Discard chunks shorter than this
TIKTOKEN_ENCODING = "cl100k_base"

# Regex patterns for section heading detection in RBI circulars
_SECTION_HEADING_PATTERNS = [
    re.compile(r"^\s*(\d+\.[\d.]*)\s+[A-Z]", re.MULTILINE),  # "1.2 Section Name"
    re.compile(r"^\s*(Part\s+[IVX]+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*(Annex(?:ure)?\s+[A-Z0-9]+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*(Schedule\s+[IVX]+)", re.MULTILINE | re.IGNORECASE),
]


# ── Token counting ────────────────────────────────────────────────────────────

_tokeniser = None


def _get_tokeniser() -> object:
    """Lazy-load tiktoken tokeniser."""
    global _tokeniser  # noqa: PLW0603
    if _tokeniser is None:
        try:
            import tiktoken  # noqa: PLC0415
            _tokeniser = tiktoken.get_encoding(TIKTOKEN_ENCODING)
        except ImportError:
            # Fallback: rough approximation (1 token ≈ 4 chars)
            _tokeniser = _FallbackTokeniser()
    return _tokeniser


class _FallbackTokeniser:
    """Fallback token counter when tiktoken is not available."""
    def encode(self, text: str) -> list[int]:
        # Rough approximation: 1 token per 4 characters
        return list(range(max(1, len(text) // 4)))


def count_tokens(text: str) -> int:
    """
    Count approximate tokens in text using tiktoken cl100k_base encoding.

    Args:
        text: Input text string.

    Returns:
        Approximate token count.
    """
    tokeniser = _get_tokeniser()
    return len(tokeniser.encode(text))


# ── Section heading extraction ────────────────────────────────────────────────

def _extract_nearest_section(text: str, char_pos: int) -> str:
    """
    Find the nearest section heading before a given character position.

    Used to annotate chunks with their source section for RAG citations.

    Args:
        text: Full document text.
        char_pos: Character position of the chunk start.

    Returns:
        Section heading string, or "Introduction" if none found.
    """
    best_heading = "Introduction"
    best_pos = -1

    for pattern in _SECTION_HEADING_PATTERNS:
        for match in pattern.finditer(text[:char_pos]):
            if match.start() > best_pos:
                best_pos = match.start()
                best_heading = match.group(0).strip()[:100]  # Cap at 100 chars

    return best_heading


# ── Core chunking function ────────────────────────────────────────────────────

def chunk_text(
    text: str,
    source_document_id: str,
    source_url: str,
    chunk_size_tokens: int = DEFAULT_CHUNK_SIZE_TOKENS,
    overlap_tokens: int = DEFAULT_OVERLAP_TOKENS,
) -> list[TextChunk]:
    """
    Split text into overlapping chunks for FAISS indexing.

    The chunker works at the paragraph level first (splitting on double
    newlines), then builds windows by accumulating paragraphs until
    the token budget is reached. If a single paragraph exceeds the
    chunk size, it is split at sentence boundaries.

    Args:
        text: Full text of the regulatory document.
        source_document_id: Circular reference identifier.
                            E.g. "RBI/2024-25/73 DNBR.CC.PD.No.141"
        source_url: Original URL of the document.
        chunk_size_tokens: Maximum tokens per chunk (default 512).
        overlap_tokens: Overlap between consecutive chunks (default 128).

    Returns:
        List of TextChunk objects. Empty if text is too short.
    """
    if not text or not text.strip():
        return []

    # Normalise whitespace
    text = _normalise_whitespace(text)

    # Split into paragraphs
    paragraphs = _split_into_paragraphs(text)
    if not paragraphs:
        return []

    chunks: list[TextChunk] = []
    chunk_index = 0

    # Sliding window over paragraphs
    para_tokens = [count_tokens(p) for p in paragraphs]
    current_paras: list[tuple[int, str]] = []  # (para_idx, text)
    current_tokens = 0

    for para_idx, (para, tokens) in enumerate(zip(paragraphs, para_tokens)):
        # If a single paragraph is larger than chunk_size, split at sentences
        if tokens > chunk_size_tokens:
            # Flush current window first
            if current_paras:
                chunk = _make_chunk(
                    paras=current_paras,
                    paragraphs=paragraphs,
                    text=text,
                    chunk_index=chunk_index,
                    source_document_id=source_document_id,
                    source_url=source_url,
                )
                if chunk:
                    chunks.append(chunk)
                    chunk_index += 1
                current_paras = []
                current_tokens = 0

            # Split the large paragraph into sentence-level sub-chunks
            sub_chunks = _chunk_large_paragraph(
                para=para,
                para_idx=para_idx,
                text=text,
                chunk_index=chunk_index,
                source_document_id=source_document_id,
                source_url=source_url,
                chunk_size_tokens=chunk_size_tokens,
                overlap_tokens=overlap_tokens,
            )
            chunks.extend(sub_chunks)
            chunk_index += len(sub_chunks)
            continue

        # Add paragraph to current window
        current_paras.append((para_idx, para))
        current_tokens += tokens

        # When window is full, emit chunk and start next window with overlap
        if current_tokens >= chunk_size_tokens:
            chunk = _make_chunk(
                paras=current_paras,
                paragraphs=paragraphs,
                text=text,
                chunk_index=chunk_index,
                source_document_id=source_document_id,
                source_url=source_url,
            )
            if chunk:
                chunks.append(chunk)
                chunk_index += 1

            # Keep overlap paragraphs for next window
            overlap_budget = overlap_tokens
            overlap_paras: list[tuple[int, str]] = []
            for pidx, ptxt in reversed(current_paras):
                ptokens = count_tokens(ptxt)
                if overlap_budget <= 0:
                    break
                overlap_paras.insert(0, (pidx, ptxt))
                overlap_budget -= ptokens

            current_paras = overlap_paras
            current_tokens = sum(count_tokens(p) for _, p in current_paras)

    # Emit final window if non-empty
    if current_paras:
        chunk = _make_chunk(
            paras=current_paras,
            paragraphs=paragraphs,
            text=text,
            chunk_index=chunk_index,
            source_document_id=source_document_id,
            source_url=source_url,
        )
        if chunk:
            chunks.append(chunk)

    return chunks


def _make_chunk(
    paras: list[tuple[int, str]],
    paragraphs: list[str],
    text: str,
    chunk_index: int,
    source_document_id: str,
    source_url: str,
) -> TextChunk | None:
    """Build a TextChunk from a list of (para_idx, para_text) tuples."""
    if not paras:
        return None

    chunk_text_content = "\n\n".join(p for _, p in paras)
    token_count = count_tokens(chunk_text_content)

    if token_count < MIN_CHUNK_SIZE_TOKENS:
        return None

    # Find character offsets in original text
    first_para = paras[0][1]
    last_para = paras[-1][1]
    char_start = text.find(first_para)
    char_end_raw = text.find(last_para)
    char_end = char_end_raw + len(last_para) if char_end_raw >= 0 else char_start + len(chunk_text_content)

    section_hint = _extract_nearest_section(text, max(0, char_start))

    return TextChunk(
        text=chunk_text_content,
        chunk_index=chunk_index,
        source_document_id=source_document_id,
        source_url=source_url,
        section_hint=section_hint,
        char_start=max(0, char_start),
        char_end=char_end,
        token_count=token_count,
    )


def _chunk_large_paragraph(
    para: str,
    para_idx: int,
    text: str,
    chunk_index: int,
    source_document_id: str,
    source_url: str,
    chunk_size_tokens: int,
    overlap_tokens: int,
) -> list[TextChunk]:
    """Split a paragraph that exceeds chunk_size_tokens at sentence boundaries."""
    sentences = _split_into_sentences(para)
    chunks: list[TextChunk] = []
    current_sents: list[str] = []
    current_tokens = 0
    local_idx = chunk_index

    for sent in sentences:
        sent_tokens = count_tokens(sent)
        current_sents.append(sent)
        current_tokens += sent_tokens

        if current_tokens >= chunk_size_tokens:
            chunk_text_content = " ".join(current_sents)
            token_count = count_tokens(chunk_text_content)
            if token_count >= MIN_CHUNK_SIZE_TOKENS:
                char_start = text.find(current_sents[0])
                chunks.append(TextChunk(
                    text=chunk_text_content,
                    chunk_index=local_idx,
                    source_document_id=source_document_id,
                    source_url=source_url,
                    section_hint=_extract_nearest_section(text, max(0, char_start)),
                    char_start=max(0, char_start),
                    char_end=max(0, char_start) + len(chunk_text_content),
                    token_count=token_count,
                ))
                local_idx += 1

            # Keep overlap sentences
            overlap_budget = overlap_tokens
            overlap_sents: list[str] = []
            for s in reversed(current_sents):
                if overlap_budget <= 0:
                    break
                overlap_sents.insert(0, s)
                overlap_budget -= count_tokens(s)

            current_sents = overlap_sents
            current_tokens = sum(count_tokens(s) for s in current_sents)

    if current_sents:
        chunk_text_content = " ".join(current_sents)
        if count_tokens(chunk_text_content) >= MIN_CHUNK_SIZE_TOKENS:
            char_start = text.find(current_sents[0])
            chunks.append(TextChunk(
                text=chunk_text_content,
                chunk_index=local_idx,
                source_document_id=source_document_id,
                source_url=source_url,
                section_hint=_extract_nearest_section(text, max(0, char_start)),
                char_start=max(0, char_start),
                char_end=max(0, char_start) + len(chunk_text_content),
                token_count=count_tokens(chunk_text_content),
            ))

    return chunks


# ── Text normalisation helpers ────────────────────────────────────────────────

def _normalise_whitespace(text: str) -> str:
    """Normalise whitespace: collapse multiple spaces, normalise line endings."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Collapse 3+ newlines to double newline (paragraph break)
    text = re.sub(r"\n{3,}", "\n\n", text)
    # Collapse multiple spaces on a line
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


def _split_into_paragraphs(text: str) -> list[str]:
    """Split text on double newlines, filtering empty paragraphs."""
    paragraphs = re.split(r"\n\n+", text)
    return [p.strip() for p in paragraphs if p.strip() and len(p.strip()) > 20]


def _split_into_sentences(text: str) -> list[str]:
    """
    Split text into sentences using a simple rule-based splitter.

    Handles common abbreviations in legal/regulatory text to avoid
    false sentence breaks at "e.g.", "i.e.", "viz.", "etc.", "No.", "Rs.".
    """
    # Protect common abbreviations
    protected = text
    abbreviations = [
        "e.g.", "i.e.", "viz.", "etc.", "No.", "Rs.", "RBI.", "NBFC.",
        "KYC.", "AML.", "PAN.", "Sec.", "Art.", "Fig.", "Vol.", "para.",
    ]
    placeholders: dict[str, str] = {}
    for i, abbr in enumerate(abbreviations):
        placeholder = f"__ABBR{i}__"
        protected = protected.replace(abbr, placeholder)
        placeholders[placeholder] = abbr

    # Split on sentence-ending punctuation
    raw_sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\(])", protected)

    # Restore abbreviations
    sentences = []
    for sent in raw_sentences:
        for placeholder, abbr in placeholders.items():
            sent = sent.replace(placeholder, abbr)
        sent = sent.strip()
        if sent:
            sentences.append(sent)

    return sentences if sentences else [text]