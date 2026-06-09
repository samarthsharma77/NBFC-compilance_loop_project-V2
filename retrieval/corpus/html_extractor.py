"""
ComplianceLoop — HTML Text Extractor
======================================
Extracts clean text from RBI circular HTML pages using BeautifulSoup.

RBI's website publishes circulars in multiple formats. Some are available
as HTML pages directly (especially recent ones under the new portal).
The Scrapy spiders download these pages; this extractor converts the
raw HTML to clean text for chunking and embedding.

Extraction strategy:
  1. Parse with lxml (faster and more lenient than html.parser)
  2. Remove navigation, headers, footers, scripts, styles
  3. Extract the main content area (RBI pages have consistent structure)
  4. Clean text: remove excess whitespace, normalise Unicode

RBI portal-specific selectors:
  The RBI website has changed its structure multiple times. This extractor
  tries multiple content selectors in priority order, falling back to
  body text extraction if none match.
"""

from __future__ import annotations

import re
import logging
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Content selectors in priority order ──────────────────────────────────────
# Try each CSS selector; use the first one that finds content.
# These target the main circular body on rbi.org.in

_CONTENT_SELECTORS = [
    "div.MainContent",              # RBI main content div (2020+ portal)
    "div#MainContent",              # Alternate ID form
    "div.content-body",             # Some sub-pages
    "div.notification-content",     # Notification pages
    "article",                      # Generic article element
    "main",                         # HTML5 main content
    "div.container-fluid .row",     # Bootstrap layout fallback
    "body",                         # Last resort — full body
]

# Tags to remove completely (navigation, non-content)
_REMOVE_TAGS = [
    "script", "style", "nav", "header", "footer",
    "noscript", "iframe", "form", "button", "input",
    "aside", "advertisement", "breadcrumb",
]

# CSS classes/IDs that indicate non-content areas
_REMOVE_SELECTORS = [
    ".navigation", ".nav", ".menu", ".sidebar",
    ".breadcrumb", ".pagination", ".footer", ".header",
    "#navigation", "#nav", "#menu", "#sidebar",
    "#footer", "#header", ".print-hide",
]


def extract_text_from_html(
    html: str | bytes,
    source_url: str = "",
    extract_title: bool = True,
) -> str:
    """
    Extract clean text from an HTML page.

    Args:
        html: Raw HTML string or bytes.
        source_url: Original URL (used for logging and heuristics).
        extract_title: If True, prepend the page title to extracted text.

    Returns:
        Clean text suitable for chunking and embedding.

    Raises:
        ValueError: If html is empty.
        ImportError: If beautifulsoup4 or lxml is not installed.
    """
    if not html:
        raise ValueError("Cannot extract text from empty HTML.")

    try:
        from bs4 import BeautifulSoup, Tag  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "beautifulsoup4 is required for HTML extraction. "
            "Install with: pip install -r requirements/pipeline.txt"
        ) from exc

    # Parse HTML
    if isinstance(html, bytes):
        soup = BeautifulSoup(html, "lxml")
    else:
        soup = BeautifulSoup(html, "lxml")

    # Extract title if requested
    title_text = ""
    if extract_title:
        title_tag = soup.find("title")
        if title_tag:
            title_text = title_tag.get_text(strip=True)

    # Remove non-content elements
    for tag_name in _REMOVE_TAGS:
        for tag in soup.find_all(tag_name):
            tag.decompose()

    for selector in _REMOVE_SELECTORS:
        for element in soup.select(selector):
            element.decompose()

    # Find main content area
    content = _find_main_content(soup)

    # Extract text
    raw_text = content.get_text(separator="\n", strip=True)

    if not raw_text.strip():
        logger.warning(
            "html.extraction.empty",
            source_url=source_url,
        )
        return ""

    # Clean the extracted text
    text = _clean_html_text(raw_text)

    # Prepend title if available
    if title_text and extract_title:
        title_clean = _clean_html_text(title_text)
        if title_clean and title_clean not in text[:200]:
            text = f"{title_clean}\n\n{text}"

    logger.debug(
        "html.extraction.completed",
        source_url=source_url,
        char_count=len(text),
    )

    return text


def extract_circular_metadata(html: str | bytes) -> dict[str, str]:
    """
    Extract structured metadata from an RBI circular HTML page.

    Attempts to extract:
      - Circular reference number
      - Publication date
      - Effective date
      - Circular title
      - Department

    Args:
        html: Raw HTML string or bytes.

    Returns:
        Dict with extracted metadata. Missing fields are empty strings.
    """
    try:
        from bs4 import BeautifulSoup  # noqa: PLC0415
    except ImportError:
        return {}

    if isinstance(html, bytes):
        soup = BeautifulSoup(html, "lxml")
    else:
        soup = BeautifulSoup(html, "lxml")

    metadata: dict[str, str] = {
        "circular_reference": "",
        "publication_date": "",
        "effective_date": "",
        "title": "",
        "department": "",
    }

    # Title
    title_tag = soup.find("h1") or soup.find("h2") or soup.find("title")
    if title_tag:
        metadata["title"] = title_tag.get_text(strip=True)[:200]

    full_text = soup.get_text(" ", strip=True)

    # Circular reference: RBI/YYYY-YY/NNN or similar
    ref_match = re.search(
        r"RBI/\d{4}-\d{2,4}/\d+\s+\S+(?:/\S+)+",
        full_text,
    )
    if ref_match:
        metadata["circular_reference"] = ref_match.group(0).strip()[:200]

    # Date patterns: DD Month YYYY or Month DD, YYYY
    date_match = re.search(
        r"\b(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|"
        r"September|October|November|December)\s+\d{4})\b",
        full_text,
        re.IGNORECASE,
    )
    if date_match:
        metadata["publication_date"] = date_match.group(1)

    return metadata


# ── Content area finder ───────────────────────────────────────────────────────

def _find_main_content(soup: Any) -> Any:
    """
    Find the main content element using the priority selector list.

    Returns the first matching element, or the body as fallback.
    """
    from bs4 import BeautifulSoup  # noqa: PLC0415

    for selector in _CONTENT_SELECTORS:
        elements = soup.select(selector)
        if elements:
            # If multiple matches, pick the one with the most text content
            best = max(elements, key=lambda e: len(e.get_text(strip=True)))
            if len(best.get_text(strip=True)) > 200:
                return best

    # Last resort: return full soup
    return soup


# ── Text cleaning ─────────────────────────────────────────────────────────────

def _clean_html_text(text: str) -> str:
    """
    Clean raw text extracted from HTML.

    - Normalise Unicode
    - Remove excess whitespace
    - Remove repeated blank lines
    - Strip control characters
    """
    # Normalise Unicode
    replacements = {
        "\u00a0": " ",    # non-breaking space
        "\u2013": "-",    # en dash
        "\u2014": "--",   # em dash
        "\u2018": "'",    # left single quote
        "\u2019": "'",    # right single quote
        "\u201c": '"',    # left double quote
        "\u201d": '"',    # right double quote
        "\u00ad": "",     # soft hyphen
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)

    # Remove control characters (except newlines and tabs)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Collapse multiple spaces
    text = re.sub(r"[ \t]{2,}", " ", text)

    # Collapse multiple newlines
    text = re.sub(r"\n{3,}", "\n\n", text)

    # Remove lines that are just punctuation or numbers (nav artefacts)
    lines = text.split("\n")
    cleaned_lines = [
        line for line in lines
        if len(line.strip()) > 3 or (line.strip() and line.strip()[0].isalpha())
    ]
    text = "\n".join(cleaned_lines)

    return text.strip()