# retrieval/corpus/__init__.py
from retrieval.corpus.pdf_extractor import extract_text_from_pdf, PDFExtractionError, ScannedPDFError
from retrieval.corpus.html_extractor import extract_text_from_html, extract_circular_metadata
from retrieval.corpus.preprocessor import preprocess, PreprocessedDocument, ACRONYM_EXPANSIONS

__all__ = [
    "extract_text_from_pdf",
    "PDFExtractionError",
    "ScannedPDFError",
    "extract_text_from_html",
    "extract_circular_metadata",
    "preprocess",
    "PreprocessedDocument",
    "ACRONYM_EXPANSIONS",
]