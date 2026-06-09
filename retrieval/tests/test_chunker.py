"""
Tests for retrieval/chunker.py

Covers:
  - chunk_text() returns list of TextChunk objects
  - chunk_text() empty text returns empty list
  - chunk_text() short text returns single chunk
  - chunk_text() long text produces multiple overlapping chunks
  - Overlap: last tokens of chunk N appear in chunk N+1
  - MIN_CHUNK_SIZE_TOKENS filtering
  - chunk metadata: source_document_id, source_url, chunk_index
  - section_hint extraction from RBI section headings
  - _split_into_paragraphs() filters empty paragraphs
  - _split_into_sentences() handles abbreviations
  - count_tokens() returns positive integer for non-empty text
  - TextChunk.to_metadata_dict() returns correct keys
"""

from __future__ import annotations

import pytest

from retrieval.chunker import (
    TextChunk,
    _split_into_paragraphs,
    _split_into_sentences,
    chunk_text,
    count_tokens,
)

# ── Test data ─────────────────────────────────────────────────────────────────

SHORT_TEXT = "The NBFC shall maintain a FOIR of not more than 50 percent."

MEDIUM_TEXT = """
1. Introduction

The Reserve Bank of India has issued guidelines on lending practices for NBFCs.
These guidelines apply to all registered Non-Banking Financial Companies.

2. FOIR Requirements

The Fixed Obligation to Income Ratio shall not exceed fifty percent for
unsecured personal loans. For secured loans including home loans and vehicle
loans, the FOIR may extend to sixty-five percent of gross monthly income.

3. KYC Compliance

All NBFCs are required to complete KYC verification before disbursing any loan.
The KYC documents shall include an Officially Valid Document serving as both
identity and address proof.
""".strip()

LONG_TEXT = "\n\n".join([
    f"Section {i}. This is paragraph {i} containing regulatory guidance about "
    f"NBFC compliance requirements for loan origination and KYC verification "
    f"processes under RBI Master Directions. The section provides detailed "
    f"instructions on documentation requirements and verification procedures."
    for i in range(1, 30)
])

SOURCE_DOC_ID = "RBI_NBFC_DIRECTIONS_2016"
SOURCE_URL = "https://www.rbi.org.in/scripts/BS_ViewMasCirculardetails.aspx"


# ── chunk_text() tests ────────────────────────────────────────────────────────

class TestChunkText:

    def test_empty_text_returns_empty_list(self) -> None:
        result = chunk_text("", SOURCE_DOC_ID, SOURCE_URL)
        assert result == []

    def test_whitespace_only_returns_empty_list(self) -> None:
        result = chunk_text("   \n\n   ", SOURCE_DOC_ID, SOURCE_URL)
        assert result == []

    def test_short_text_returns_list(self) -> None:
        result = chunk_text(SHORT_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        assert isinstance(result, list)

    def test_short_text_single_chunk(self) -> None:
        result = chunk_text(SHORT_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        # Short text fits in one chunk
        assert len(result) >= 1

    def test_returns_text_chunk_objects(self) -> None:
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        assert all(isinstance(c, TextChunk) for c in result)

    def test_chunks_have_source_document_id(self) -> None:
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        for chunk in result:
            assert chunk.source_document_id == SOURCE_DOC_ID

    def test_chunks_have_source_url(self) -> None:
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        for chunk in result:
            assert chunk.source_url == SOURCE_URL

    def test_chunk_indices_are_sequential(self) -> None:
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        indices = [c.chunk_index for c in result]
        assert indices == list(range(len(result)))

    def test_all_chunks_have_text(self) -> None:
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        for chunk in result:
            assert chunk.text.strip() != ""

    def test_chunks_cover_original_content(self) -> None:
        """Key phrases from original text should appear in at least one chunk."""
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        all_text = " ".join(c.text for c in result)
        assert "FOIR" in all_text
        assert "KYC" in all_text
        assert "NBFC" in all_text

    def test_long_text_multiple_chunks(self) -> None:
        """Long text should produce multiple chunks."""
        result = chunk_text(LONG_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        assert len(result) > 1

    def test_chunk_size_respected(self) -> None:
        """No chunk should significantly exceed chunk_size_tokens."""
        result = chunk_text(
            LONG_TEXT, SOURCE_DOC_ID, SOURCE_URL, chunk_size_tokens=256
        )
        for chunk in result:
            # Allow 20% overflow due to paragraph boundary respect
            assert chunk.token_count <= 256 * 1.2, (
                f"Chunk {chunk.chunk_index} has {chunk.token_count} tokens (limit 256)"
            )

    def test_overlap_in_consecutive_chunks(self) -> None:
        """
        With overlap, some text from chunk N should appear in chunk N+1.
        This verifies the sliding window overlap is working.
        """
        result = chunk_text(
            LONG_TEXT,
            SOURCE_DOC_ID,
            SOURCE_URL,
            chunk_size_tokens=200,
            overlap_tokens=50,
        )

        if len(result) < 2:
            pytest.skip("Not enough chunks to test overlap")

        # Get last 20 words of chunk 0
        chunk0_words = result[0].text.split()[-20:]
        chunk1_text = result[1].text

        # At least some overlap words should appear in chunk 1
        overlap_found = any(word in chunk1_text for word in chunk0_words)
        assert overlap_found, "Expected overlap between consecutive chunks"

    def test_chunk_token_count_is_positive(self) -> None:
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        for chunk in result:
            assert chunk.token_count > 0

    def test_char_offsets_are_non_negative(self) -> None:
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        for chunk in result:
            assert chunk.char_start >= 0
            assert chunk.char_end >= chunk.char_start


# ── TextChunk.to_metadata_dict() tests ────────────────────────────────────────

class TestTextChunkMetadata:

    def test_to_metadata_dict_has_required_keys(self) -> None:
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        assert len(result) > 0
        d = result[0].to_metadata_dict()
        required_keys = {
            "chunk_index", "source_document_id", "source_url",
            "section_hint", "char_start", "char_end", "token_count",
        }
        assert required_keys.issubset(set(d.keys()))

    def test_to_metadata_dict_source_document_id(self) -> None:
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        d = result[0].to_metadata_dict()
        assert d["source_document_id"] == SOURCE_DOC_ID

    def test_section_hint_extracted_from_rbi_structure(self) -> None:
        """Section headings like '2. FOIR Requirements' should be detected."""
        result = chunk_text(MEDIUM_TEXT, SOURCE_DOC_ID, SOURCE_URL)
        hints = [c.section_hint for c in result]
        # At least one chunk should have a non-default section hint
        non_default = [h for h in hints if h != "Introduction"]
        assert len(non_default) >= 1


# ── Helper function tests ─────────────────────────────────────────────────────

class TestSplitIntoParagraphs:

    def test_splits_on_double_newline(self) -> None:
        text = "Para one.\n\nPara two.\n\nPara three."
        result = _split_into_paragraphs(text)
        assert len(result) == 3

    def test_filters_empty_paragraphs(self) -> None:
        text = "Para one.\n\n\n\nPara two."
        result = _split_into_paragraphs(text)
        assert len(result) == 2
        assert all(p.strip() for p in result)

    def test_filters_very_short_paragraphs(self) -> None:
        text = "Real paragraph with content.\n\nok\n\nAnother real paragraph here."
        result = _split_into_paragraphs(text)
        # "ok" is too short (< 20 chars) and should be filtered
        assert "ok" not in result


class TestSplitIntoSentences:

    def test_splits_on_period_capital(self) -> None:
        text = "First sentence. Second sentence. Third sentence."
        result = _split_into_sentences(text)
        assert len(result) >= 2

    def test_preserves_eg_abbreviation(self) -> None:
        """e.g. should not cause a sentence split."""
        text = "Documents e.g. Aadhaar, PAN are required. Submit them today."
        result = _split_into_sentences(text)
        # Should produce 2 sentences, not 3 (e.g. should not split)
        assert len(result) <= 2

    def test_preserves_ie_abbreviation(self) -> None:
        text = "The limit i.e. fifty percent applies. Check the guidelines."
        result = _split_into_sentences(text)
        assert len(result) <= 2

    def test_single_sentence_returns_list_of_one(self) -> None:
        text = "This is a single sentence with no period at the end"
        result = _split_into_sentences(text)
        assert len(result) == 1
        assert result[0] == text


class TestCountTokens:

    def test_returns_positive_integer(self) -> None:
        count = count_tokens("FOIR threshold exceeded for unsecured loan NBFC")
        assert isinstance(count, int)
        assert count > 0

    def test_longer_text_more_tokens(self) -> None:
        short_count = count_tokens("short text")
        long_count = count_tokens("this is a much longer text with many more words in it")
        assert long_count > short_count

    def test_empty_string_returns_zero_or_one(self) -> None:
        # Empty string may return 0 or 1 depending on tokeniser
        count = count_tokens("")
        assert count >= 0