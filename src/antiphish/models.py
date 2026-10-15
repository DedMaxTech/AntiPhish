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
    scope_id: str | None = None


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
    scope_id: str | None = None
    navigation_url: str | None = field(default=None, repr=False, metadata={"private": True})
    depth: int = 0


@dataclass(slots=True)
class FormFinding:
    id: str
    scope_id: str
    fields: list[str]
    sensitive_types: list[str]
    method: str
    destination: str | None = None
    destination_host: str | None = None
    collector_observed: bool = False
    external: bool = False
    selector: str | None = None
    safe_structure: str | None = None


@dataclass(slots=True)
class PageFinding:
    id: str
    sha256: str
    url: str | None = None
    host: str | None = None
    title: str = ""
    complete: bool = True
    forms: list[FormFinding] = field(default_factory=list)
    claimed_brands: list[str] = field(default_factory=list)
    identity_source: str = "dom"
    resources: list[dict[str, Any]] = field(default_factory=list)
    screenshot_sha256: str | None = None
    text: str = field(default="", repr=False, metadata={"private": True})
    identity_text: str = field(default="", repr=False, metadata={"private": True})


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
    schema_version: str = "2.0"
    analysis_status: AnalysisStatus = AnalysisStatus.COMPLETE
    verdict: Verdict = Verdict.NOT_DETECTED
    configuration: dict[str, Any] = field(default_factory=dict)
    input: dict[str, Any] = field(default_factory=dict)
    reason_codes: list[Evidence] = field(default_factory=list)
    urls: list[UrlFinding] = field(default_factory=list)
    pages: list[PageFinding] = field(default_factory=list)
    routes: list[dict[str, Any]] = field(default_factory=list)
    reputation: dict[str, Any] = field(default_factory=dict)
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
        return _enum_values(_public_dataclass(self))


def _public_dataclass(value: Any) -> Any:
    from dataclasses import fields, is_dataclass
    if is_dataclass(value):
        return {f.name: _public_dataclass(getattr(value, f.name)) for f in fields(value) if not f.metadata.get("private")}
    if isinstance(value, dict):
        return {k: _public_dataclass(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_public_dataclass(v) for v in value]
    return value


def _enum_values(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _enum_values(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_enum_values(v) for v in value]
    return value
