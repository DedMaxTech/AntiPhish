from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESOURCE_DIR = PROJECT_ROOT / "resources"
ARTIFACT_DIR = PROJECT_ROOT / "artifacts"
MODEL_DIR = PROJECT_ROOT / "models"
REPORT_DIR = PROJECT_ROOT / "reports"
DEFAULT_KB = ARTIFACT_DIR / "knowledge.sqlite"


@dataclass(frozen=True, slots=True)
class Limits:
    max_input_bytes: int = 50 * 1024 * 1024
    max_total_extracted_bytes: int = 200 * 1024 * 1024
    max_attachment_bytes: int = 40 * 1024 * 1024
    max_archive_entries: int = 2_000
    max_archive_ratio: float = 100.0
    max_archive_members: int = 2_000
    max_archive_uncompressed_bytes: int = 200 * 1024 * 1024
    max_compression_ratio: float = 100.0
    max_recursion_depth: int = 3
    max_urls: int = 500
    max_forms: int = 100
    max_html_chars: int = 5_000_000
    max_text_chars: int = 2_000_000
    max_xml_bytes: int = 20 * 1024 * 1024
    max_pdf_pages: int = 100
    max_pages: int = 100
    max_images_per_document: int = 40
    max_redirects: int = 7
    network_timeout_seconds: float = 12.0
    max_http_bytes: int = 10 * 1024 * 1024


DEFAULT_LIMITS = Limits()
