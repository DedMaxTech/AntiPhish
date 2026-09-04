from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    NOT_DETECTED = "NOT_DETECTED"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


class AnalysisStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(slots=True)
class Evidence:
    code: str
    severity: Severity
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    source: str | None = None
    independent_group: str = "generic"


@dataclass(slots=True)
class UrlFinding:
    original: str
    normalized: str | None = None
    host: str | None = None
    registered_domain: str | None = None
    displayed_text: str | None = None
    source: str | None = None
    flags: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    fetch_status: str | None = None


@dataclass(slots=True)
class AttachmentFinding:
    name: str
    media_type: str
    size: int
    sha256: str
    status: str = "ANALYZED"
    evidence_codes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class BrandFinding:
    brand: str
    confidence: float
    sources: list[str]
    official_domains: list[str]
    observed_domains: list[str]


@dataclass(slots=True)
class AnalysisReport:
    schema_version: str = "1.0"
    analysis_status: AnalysisStatus = AnalysisStatus.COMPLETE
    verdict: Verdict = Verdict.NOT_DETECTED
    configuration: dict[str, Any] = field(default_factory=dict)
    input: dict[str, Any] = field(default_factory=dict)
    reason_codes: list[Evidence] = field(default_factory=list)
    urls: list[UrlFinding] = field(default_factory=list)
    attachments: list[AttachmentFinding] = field(default_factory=list)
    brands: list[BrandFinding] = field(default_factory=list)
    fingerprints: dict[str, Any] = field(default_factory=dict)
    model_evidence: list[dict[str, Any]] = field(default_factory=list)
    model_warnings: list[str] = field(default_factory=list)
    network_activity: list[dict[str, Any]] = field(default_factory=list)
    network_warnings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    timings_ms: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _enum_values(asdict(self))


def _enum_values(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _enum_values(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_enum_values(v) for v in value]
    return value
