"""
ComplianceLoop — PDF Text Extractor
=====================================
Extracts clean text from RBI circular PDFs using pdfminer.six.

RBI publishes most master directions and major circulars as PDFs.
This extractor handles:
  - Single-column and multi-column layouts
  - Embedded fonts (common in RBI PDFs)
  - Tables (extracted as text, structure lost — acceptable for RAG)
  - Headers and footers (detected and stripped heuristically)
  - Footnotes (kept inline — they often contain important clarifications)

Known limitations:
  - Scanned PDFs (image-based) produce empty text. RBI's recent PDFs
    are text-based; older ones may be scanned. If text extraction
    yields < 100 characters, the extractor raises ScannedPDFError.
  - Complex mathematical formulas are lost.
  - Tables lose column alignment but text content is preserved.

pdfminer.six is used instead of pypdf because it handles complex
font encoding and CIDFont maps more reliably for government PDFs.
"""

from __future__ import annotations

import io
import logging
import re
from pathlib import Path
from typing import BinaryIO

import structlog

logger = structlog.get_logger(__name__)


class PDFExtractionError(Exception):
    """Raised when PDF text extraction fails completely."""


class ScannedPDFError(PDFExtractionError):
    """Raised when PDF appears to be scanned (no extractable text)."""


# ── Minimum text length to consider extraction successful ────────────────────
MIN_EXTRACTABLE_CHARS = 100

# ── Header/footer patterns common in RBI PDFs ────────────────────────────────
_HEADER_FOOTER_PATTERNS = [
    re.compile(r"^\s*Page\s+\d+\s+of\s+\d+\s*$", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Reserve Bank of India\s*$", re.MULTILINE),
    re.compile(r"^\s*www\.rbi\.org\.in\s*$", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*\d{1,3}\s*$", re.MULTILINE),   # Standalone page numbers
    re.compile(r"RBI/\d{4}-\d{2}/\d+", re.MULTILINE),  # Circular reference in header
]


def extract_text_from_pdf(
    source: str | Path | bytes | BinaryIO,
    strip_headers_footers: bool = True,
) -> str:
    """
    Extract text from a PDF file or bytes object.

    Args:
        source: Path to PDF file, raw bytes, or file-like object.
        strip_headers_footers: If True, attempt to remove repeated
                               header/footer content from each page.

    Returns:
        Extracted text as a single string with page breaks normalised
        to double newlines.

    Raises:
        PDFExtractionError: If pdfminer fails to process the file.
        ScannedPDFError: If the PDF appears to be scanned (< 100 chars extracted).
        ImportError: If pdfminer.six is not installed.
    """
    try:
        from pdfminer.high_level import extract_text_to_fp  # noqa: PLC0415
        from pdfminer.layout import LAParams  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "pdfminer.six is required for PDF extraction. "
            "Install with: pip install -r requirements/pipeline.txt"
        ) from exc

    # Prepare input
    if isinstance(source, (str, Path)):
        with open(source, "rb") as f:
            pdf_bytes = f.read()
    elif isinstance(source, bytes):
        pdf_bytes = source
    else:
        pdf_bytes = source.read()

    # Configure pdfminer layout analysis
    # all_texts=True: extract all text including rotated text
    # line_margin=0.5: generous line margin for government PDFs
    laparams = LAParams(
        line_overlap=0.5,
        char_margin=2.0,
        line_margin=0.5,
        word_margin=0.1,
        boxes_flow=0.5,
        detect_vertical=False,
        all_texts=True,
    )

    output_buffer = io.StringIO()

    try:
        extract_text_to_fp(
            io.BytesIO(pdf_bytes),
            output_buffer,
            laparams=laparams,
            output_type="text",
            codec="utf-8",
        )
    except Exception as exc:
        raise PDFExtractionError(
            f"pdfminer failed to extract text: {exc}"
        ) from exc

    raw_text = output_buffer.getvalue()

    if len(raw_text.strip()) < MIN_EXTRACTABLE_CHARS:
        raise ScannedPDFError(
            f"PDF text extraction yielded only {len(raw_text.strip())} characters. "
            "This PDF may be scanned (image-based). "
            "OCR is not supported — obtain the text version of this circular."
        )

    # Post-process
    text = _clean_extracted_text(raw_text, strip_headers_footers)

    logger.debug(
        "pdf.extraction.completed",
        char_count=len(text),
        original_char_count=len(raw_text),
    )

    return text


def extract_text_from_pdf_pages(
    source: str | Path | bytes | BinaryIO,
) -> list[str]:
    """
    Extract text page by page from a PDF.

    Returns a list of strings, one per page. Useful for identifying
    which page a section heading appears on for better chunk metadata.

    Args:
        source: Path, bytes, or file-like object.

    Returns:
        List of page text strings.

    Raises:
        PDFExtractionError, ScannedPDFError, ImportError.
    """
    try:
        from pdfminer.high_level import extract_pages  # noqa: PLC0415
        from pdfminer.layout import LAParams, LTTextContainer  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError("pdfminer.six is required.") from exc

    if isinstance(source, (str, Path)):
        with open(source, "rb") as f:
            pdf_bytes = f.read()
    elif isinstance(source, bytes):
        pdf_bytes = source
    else:
        pdf_bytes = source.read()

    laparams = LAParams(
        line_margin=0.5,
        char_margin=2.0,
        word_margin=0.1,
    )

    pages: list[str] = []
    try:
        for page_layout in extract_pages(io.BytesIO(pdf_bytes), laparams=laparams):
            page_text_parts = []
            for element in page_layout:
                if isinstance(element, LTTextContainer):
                    page_text_parts.append(element.get_text())
            pages.append("".join(page_text_parts))
    except Exception as exc:
        raise PDFExtractionError(f"Page extraction failed: {exc}") from exc

    total_chars = sum(len(p.strip()) for p in pages)
    if total_chars < MIN_EXTRACTABLE_CHARS:
        raise ScannedPDFError("PDF appears to be scanned — insufficient text extracted.")

    return pages


# ── Text cleaning ─────────────────────────────────────────────────────────────

def _clean_extracted_text(text: str, strip_headers_footers: bool) -> str:
    """
    Clean raw pdfminer output for use in the chunker.

    Steps:
      1. Normalise Unicode (ligatures, smart quotes)
      2. Strip page headers/footers (if requested)
      3. Remove hyphenation artifacts (end-of-line hyphens)
      4. Normalise whitespace
    """
    # Normalise common Unicode ligatures and special chars
    replacements = {
        "\ufb01": "fi",   # fi ligature
        "\ufb02": "fl",   # fl ligature
        "\u2013": "-",    # en dash
        "\u2014": "--",   # em dash
        "\u2018": "'",    # left single quote
        "\u2019": "'",    # right single quote
        "\u201c": '"',    # left double quote
        "\u201d": '"',    # right double quote
        "\u00a0": " ",    # non-breaking space
        "\u00ad": "",     # soft hyphen
        "\x0c": "\n\n",   # form feed (page break)
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)

    if strip_headers_footers:
        for pattern in _HEADER_FOOTER_PATTERNS:
            text = pattern.sub("", text)

    # Remove hyphenation artifacts: word- \n word → word word
    text = re.sub(r"(\w)-\s*\n\s*(\w)", r"\1\2", text)

    # Normalise whitespace
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()

    return text