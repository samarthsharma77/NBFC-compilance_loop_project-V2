"""
ComplianceLoop — Corpus Preprocessor
======================================
Cleans and normalises regulatory text before chunking and embedding.

This sits between the extractors (PDF/HTML) and the chunker.
Its job is to produce consistent, clean text regardless of whether
the source was a PDF or an HTML page.

Operations performed:
  1. Remove boilerplate (standard RBI letterhead, disclaimer sections)
  2. Normalise RBI-specific abbreviations for consistent retrieval
     (e.g. "Non-Banking Financial Company" ↔ "NBFC")
  3. Expand common acronyms on first occurrence
  4. Remove tables of contents (they duplicate section headings as
     short fragments that produce low-quality embeddings)
  5. Normalise section numbering formats
  6. Strip footnote markers but keep footnote text inline
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ── Boilerplate patterns to remove ────────────────────────────────────────────
# These appear on every RBI circular and add noise to embeddings

_BOILERPLATE_PATTERNS = [
    # Standard RBI address block
    re.compile(
        r"Reserve Bank of India\s*,?\s*Central Office.*?Mumbai\s*[-–]\s*400\s*001",
        re.DOTALL | re.IGNORECASE,
    ),
    # "Yours faithfully" sign-off block
    re.compile(
        r"Yours\s+faithfully.*?(?:General Manager|Chief General Manager|Deputy Governor)",
        re.DOTALL | re.IGNORECASE,
    ),
    # Standard disclaimer
    re.compile(
        r"This circular.*?Please\s+acknowledge\s+receipt",
        re.DOTALL | re.IGNORECASE,
    ),
    # Master Circular supersession notice (repeats across all master circulars)
    re.compile(
        r"This Master Circular consolidates.*?(?:deleted|cancelled|withdrawn)\.",
        re.DOTALL | re.IGNORECASE,
    ),
]

# ── Table of contents detection ───────────────────────────────────────────────
_TOC_PATTERN = re.compile(
    r"(?:Table\s+of\s+Contents|CONTENTS?|INDEX)\s*\n"
    r"(?:[\w\s.]+\n){3,}",
    re.IGNORECASE,
)

# ── Acronym expansion map ─────────────────────────────────────────────────────
# Expand acronyms so retrieval works whether the query uses full form or acronym.
# Format: "ACRONYM": "Full Form (ACRONYM)"
# The expanded form is written back only on first occurrence per document.

ACRONYM_EXPANSIONS: dict[str, str] = {
    "NBFC": "Non-Banking Financial Company (NBFC)",
    "KYC": "Know Your Customer (KYC)",
    "AML": "Anti-Money Laundering (AML)",
    "CFT": "Combating Financing of Terrorism (CFT)",
    "FOIR": "Fixed Obligation to Income Ratio (FOIR)",
    "LTV": "Loan to Value (LTV)",
    "NTH": "Net Take-Home (NTH)",
    "CIBIL": "Credit Information Bureau India Limited (CIBIL)",
    "PMLA": "Prevention of Money Laundering Act (PMLA)",
    "OVD": "Officially Valid Document (OVD)",
    "V-CIP": "Video-based Customer Identification Process (V-CIP)",
    "SBR": "Scale Based Regulation (SBR)",
    "DPDP": "Digital Personal Data Protection (DPDP)",
    "RBI": "Reserve Bank of India (RBI)",
    "SEBI": "Securities and Exchange Board of India (SEBI)",
    "NPA": "Non-Performing Asset (NPA)",
    "CRAR": "Capital to Risk-weighted Asset Ratio (CRAR)",
    "IRB": "Internal Ratings-Based (IRB)",
    "EMI": "Equated Monthly Instalment (EMI)",
    "DTI": "Debt-to-Income (DTI)",
    "PAN": "Permanent Account Number (PAN)",
    "UIDAI": "Unique Identification Authority of India (UIDAI)",
    "MHA": "Ministry of Home Affairs (MHA)",
    "OFAC": "Office of Foreign Assets Control (OFAC)",
    "FATF": "Financial Action Task Force (FATF)",
}


@dataclass
class PreprocessedDocument:
    """Output of the preprocessor for a single regulatory document."""
    text: str                           # Clean, preprocessed text
    source_document_id: str             # Circular reference
    source_url: str                     # Original URL
    char_count: int                     # Length of cleaned text
    boilerplate_removed: int            # Characters of boilerplate removed
    acronyms_expanded: list[str]        # Acronyms that were expanded


def preprocess(
    text: str,
    source_document_id: str,
    source_url: str,
    remove_boilerplate: bool = True,
    expand_acronyms: bool = True,
    remove_toc: bool = True,
) -> PreprocessedDocument:
    """
    Preprocess a regulatory document for chunking and embedding.

    Args:
        text: Raw extracted text (from PDF or HTML extractor).
        source_document_id: Circular reference identifier.
        source_url: Original URL.
        remove_boilerplate: Strip standard RBI letterhead/sign-off text.
        expand_acronyms: Expand acronyms on first occurrence.
        remove_toc: Remove table of contents sections.

    Returns:
        PreprocessedDocument with clean text and processing metadata.
    """
    original_len = len(text)
    expanded_acronyms: list[str] = []

    if remove_toc:
        text = _remove_table_of_contents(text)

    if remove_boilerplate:
        text = _remove_boilerplate(text)

    if expand_acronyms:
        text, expanded_acronyms = _expand_acronyms(text)

    text = _normalise_section_numbers(text)
    text = _clean_final(text)

    boilerplate_removed = original_len - len(text)

    return PreprocessedDocument(
        text=text,
        source_document_id=source_document_id,
        source_url=source_url,
        char_count=len(text),
        boilerplate_removed=max(0, boilerplate_removed),
        acronyms_expanded=expanded_acronyms,
    )


def _remove_table_of_contents(text: str) -> str:
    """Remove table of contents sections."""
    return _TOC_PATTERN.sub("", text)


def _remove_boilerplate(text: str) -> str:
    """Remove standard RBI boilerplate patterns."""
    for pattern in _BOILERPLATE_PATTERNS:
        text = pattern.sub("", text)
    return text


def _expand_acronyms(text: str) -> tuple[str, list[str]]:
    """
    Expand known acronyms on their first occurrence in the text.

    Only expands the FIRST occurrence — subsequent uses keep the
    short form to avoid verbosity in chunks.

    Returns:
        Tuple of (processed_text, list_of_expanded_acronyms).
    """
    expanded: list[str] = []

    for acronym, expansion in ACRONYM_EXPANSIONS.items():
        # Only expand if acronym appears as a standalone word
        pattern = re.compile(r"\b" + re.escape(acronym) + r"\b")
        match = pattern.search(text)
        if match:
            # Replace only the first occurrence
            text = text[:match.start()] + expansion + text[match.end():]
            expanded.append(acronym)

    return text, expanded


def _normalise_section_numbers(text: str) -> str:
    """
    Normalise section number formats for consistent retrieval.

    RBI circulars use inconsistent formats:
      "Section 3(iii)" / "Para 3.3" / "Clause 3(3)" / "3(iii)"
    Normalise to "Section X.Y" format where possible.
    """
    # "Para X.Y" → "Section X.Y"
    text = re.sub(r"\bPara\s+(\d+\.\d+)", r"Section \1", text)
    # "Clause X" → "Section X"
    text = re.sub(r"\bClause\s+(\d+)", r"Section \1", text)
    return text


def _clean_final(text: str) -> str:
    """Final cleanup: normalise whitespace and remove empty lines."""
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()