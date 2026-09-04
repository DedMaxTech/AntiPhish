from __future__ import annotations

import json
import mimetypes
import time
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from .brands import detect_brands
from .config import DEFAULT_KB, DEFAULT_LIMITS, Limits, RESOURCE_DIR
from .deep import optional_deep_analysis
from .extractors import Extracted, extract_any, extract_html
from .kb import KnowledgeBase
from .models import AnalysisReport, AnalysisStatus, Evidence, Severity, UrlFinding, Verdict
from .network import safe_browser_get, safe_http_get
from .urltools import normalize_url
from .utils import bounded_text


EXIT_CODES = {Verdict.NOT_DETECTED: 0, Verdict.SUSPICIOUS: 10, Verdict.PHISHING: 20}

_STATIC_RESOURCE_SUFFIXES = {
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".webp", ".ico", ".bmp", ".woff", ".woff2", ".ttf", ".otf",
    ".eot", ".mp3", ".mp4", ".webm", ".avi", ".mov",
}


class Analyzer:
    def __init__(self, kb_path: Path = DEFAULT_KB, limits: Limits = DEFAULT_LIMITS):
        self.kb = KnowledgeBase(kb_path)
        self.limits = limits
        self.rules = json.loads((RESOURCE_DIR / "rules.json").read_text(encoding="utf-8"))

    def analyze(self, source: str | Path | bytes, *, name: str | None = None, profile: str = "quality", network: str = "offline", browser_confirmation: str | None = None) -> AnalysisReport:
        started = time.perf_counter()
        report = AnalysisReport()
        selected_profile = profile if profile in {"fast", "quality", "deep"} else "quality"
        quality_static = selected_profile != "fast"
        analysis_limits = self.limits
        if selected_profile == "fast":
            analysis_limits = replace(
                self.limits,
                max_archive_entries=min(self.limits.max_archive_entries, 500),
                max_archive_members=min(self.limits.max_archive_members, 500),
                max_archive_uncompressed_bytes=min(self.limits.max_archive_uncompressed_bytes, 50 * 1024 * 1024),
                max_urls=min(self.limits.max_urls, 100),
                max_pages=min(self.limits.max_pages, 20),
                max_pdf_pages=min(self.limits.max_pdf_pages, 20),
                max_text_chars=min(self.limits.max_text_chars, 500_000),
                max_html_chars=min(self.limits.max_html_chars, 1_000_000),
            )
        report.configuration = {
            "profile": selected_profile,
            "network_mode": network,
            "stages": [
                "bounded-static-parsing",
                "url-and-form-analysis",
                "exact-ioc-and-brand-consistency",
                *(["embedded-image-and-qr-analysis"] if quality_static else []),
                *(["local-qwen-and-siglip"] if selected_profile == "deep" else []),
            ],
            "profile_note": {
                "fast": "Сокращённые лимиты; без QR и изображений, встроенных в PDF",
                "quality": "Полный статический анализ, включая QR и изображения документов",
                "deep": "Quality плюс локальные Qwen/SigLIP; модель не блокирует самостоятельно",
            }[selected_profile],
            "network_scope": "disabled" if network == "offline" else "pending",
            "network_analysis_status": "NOT_REQUESTED" if network == "offline" else "PENDING",
        }
        extracted: Extracted
        base_url: str | None = None
        source_is_url = False
        try:
            if network not in {"offline", "http", "browser"}:
                raise ValueError(f"unsupported network mode: {network}")
            if network == "browser" and browser_confirmation != "I_UNDERSTAND":
                raise ValueError("browser mode requires --confirm-browser-risk I_UNDERSTAND")
            if isinstance(source, bytes):
                data = source
                input_name = name or "stdin.eml"
                media_type = mimetypes.guess_type(input_name)[0]
                report.input = {"kind": "bytes", "name": input_name, "size": len(data)}
                extracted = extract_any(data, input_name, media_type, analysis_limits, quality=quality_static)
            else:
                value = str(source)
                if value.lower().startswith(("http://", "https://")):
                    source_is_url = True
                    normalized = normalize_url(value)
                    base_url = normalized.normalized
                    report.input = {"kind": "url", "value": normalized.redacted, "network": network}
                    if network == "offline":
                        extracted = Extracted(kind="url", sha256="", size=0)
                        extracted.urls.append(UrlFinding(original=normalized.redacted, normalized=normalized.redacted, host=normalized.host, registered_domain=normalized.registered_domain, source="input", flags=list(normalized.flags)))
                    elif network == "http":
                        fetched = safe_http_get(value, analysis_limits)
                        base_url = fetched.final_url
                        extracted = extract_html(fetched.body, analysis_limits, base_url=base_url) if "html" in fetched.content_type else extract_any(fetched.body, urlsplit(fetched.final_url).path or "download", fetched.content_type, analysis_limits, quality=quality_static)
                        extracted.metadata["redirect_chain"] = fetched.chain
                        for url_item in extracted.urls:
                            if url_item.normalized == normalize_url(fetched.final_url).normalized:
                                url_item.redirect_chain = fetched.chain
                        report.input.update(final_url=normalize_url(fetched.final_url).redacted, http_status=fetched.status)
                        report.network_activity.append({"url": normalized.redacted, "status": "FETCHED", "http_status": fetched.status, "final_url": normalize_url(fetched.final_url).redacted})
                        report.configuration["network_analysis_status"] = "COMPLETE"
                    elif network == "browser":
                        fetched = safe_browser_get(value, analysis_limits, browser_confirmation)
                        base_url = fetched.final_url
                        extracted = extract_html(fetched.body, analysis_limits, base_url=base_url)
                        extracted.metadata["redirect_chain"] = fetched.chain
                        report.input.update(final_url=normalize_url(fetched.final_url).redacted, http_status=fetched.status)
                        report.network_activity.append({"url": normalized.redacted, "status": "BROWSER_RENDERED", "http_status": fetched.status, "final_url": normalize_url(fetched.final_url).redacted})
                        report.configuration["network_analysis_status"] = "COMPLETE"
                else:
                    path = Path(value).resolve()
                    if not path.is_file():
                        raise FileNotFoundError(path)
                    size = path.stat().st_size
                    if size > analysis_limits.max_input_bytes:
                        raise ValueError(f"input exceeds {analysis_limits.max_input_bytes} byte limit")
                    data = path.read_bytes()
                    report.input = {"kind": "file", "name": path.name, "size": size}
                    extracted = extract_any(data, path.name, mimetypes.guess_type(path.name)[0], analysis_limits, quality=quality_static)

            if source_is_url:
                report.configuration["network_scope"] = "primary-url" if network != "offline" else "disabled"
            elif network != "offline":
                report.configuration["network_scope"] = "links-extracted-from-input"
                self._enrich_extracted_links(extracted, report, network, browser_confirmation, analysis_limits, quality_static)
        except Exception as exc:
            if network != "offline":
                report.configuration["network_analysis_status"] = "FAILED"
            report.analysis_status = AnalysisStatus.FAILED
            report.warnings.append(f"Fatal analysis error: {type(exc).__name__}: {exc}")
            report.timings_ms["total"] = round((time.perf_counter() - started) * 1000, 2)
            return report

        report.input.update({"detected_type": extracted.kind, "sha256": extracted.sha256 or None})
        report.urls = _deduplicate_urls(extracted.urls)
        report.attachments = extracted.attachments
        report.fingerprints = extracted.fingerprints
        report.reason_codes = _deduplicate_evidence(extracted.evidence)
        report.warnings.extend(extracted.warnings)

        sender_domain = extracted.metadata.get("from_domain")
        brand_text = " ".join(filter(None, [extracted.metadata.get("subject", ""), extracted.text]))
        high_risk_brand_context = bool({e.code for e in report.reason_codes}.intersection({
            "SENSITIVE_FORM", "CREDENTIAL_LURE", "OBFUSCATED_LURE_SCRIPT",
            "LOGIN_IFRAME", "FINANCIAL_LOGIN_LURE", "FAKE_DOCUMENT_VIEWER",
        }))
        report.brands, brand_evidence = detect_brands(brand_text, report.urls, sender_domain, high_risk_brand_context)
        report.reason_codes.extend(brand_evidence)

        if extracted.sha256:
            ioc = self.kb.lookup_hash(extracted.sha256)
            if ioc and ioc.get("verdict") == "PHISHING":
                report.reason_codes.append(Evidence(
                    code="IOC_SHA256_MATCH", severity=Severity.CRITICAL,
                    summary="SHA-256 полностью совпал с подтверждённым вредоносным объектом",
                    details={"sha256": extracted.sha256, "source": ioc["source"], "provenance": ioc["provenance"]}, independent_group="exact-ioc",
                ))
        for attachment in report.attachments:
            ioc = self.kb.lookup_hash(attachment.sha256)
            if ioc and ioc.get("verdict") == "PHISHING":
                report.reason_codes.append(Evidence(
                    code="IOC_SHA256_MATCH", severity=Severity.CRITICAL,
                    summary="Вложение полностью совпало с подтверждённым вредоносным объектом",
                    details={"attachment": attachment.name, "sha256": attachment.sha256, "source": ioc["source"], "provenance": ioc["provenance"]}, independent_group="exact-ioc",
                ))
        for url in report.urls:
            if url.host and url.normalized:
                ioc = self.kb.lookup_url(url.host, url.normalized)
                if ioc:
                    report.reason_codes.append(Evidence(
                        code="KNOWN_BAD_URL", severity=Severity.CRITICAL,
                        summary="URL совпал с действующим подтверждённым IOC",
                        details={"url": url.original, "source": ioc["source"], "expires_at": ioc["expires_at"]}, independent_group="exact-ioc",
                    ))

        if selected_profile == "deep":
            static_context = ", ".join(sorted({e.code for e in report.reason_codes}))
            deep_text = brand_text
            if extracted.html_text:
                deep_text += "\nSTATIC HTML (untrusted, do not execute):\n" + extracted.html_text[:12000]
            if static_context:
                deep_text += "\nSTATIC EXTRACTOR FACTS:\n" + static_context
            model_evidence, warnings = optional_deep_analysis(deep_text, image_bytes=data if extracted.kind == "image" and "data" in locals() else None)
            report.model_evidence.extend(model_evidence)
            report.model_warnings.extend(warnings)
            if any(item.get("suspicious") is True for item in model_evidence):
                report.reason_codes.append(Evidence(code="MODEL_SUSPICION", severity=Severity.MEDIUM, summary="Локальная модель выделила подозрительный сценарий; этот сигнал не блокирует", details={"models": [x["model"] for x in model_evidence]}, independent_group="model"))
        elif profile not in {"fast", "quality", "deep"}:
            report.warnings.append(f"Unknown profile {profile}; quality policy used")

        if report.warnings:
            report.analysis_status = AnalysisStatus.PARTIAL
            report.reason_codes.append(Evidence(code="ANALYSIS_INCOMPLETE", severity=Severity.INFO, summary="Часть анализа не выполнена полностью", details={"warnings": report.warnings[:20]}, independent_group="status"))

        report.reason_codes = _deduplicate_evidence(report.reason_codes)
        report.verdict = self._arbitrate(report)
        report.timings_ms["total"] = round((time.perf_counter() - started) * 1000, 2)
        return report

    def _enrich_extracted_links(self, extracted: Extracted, report: AnalysisReport, network: str, browser_confirmation: str | None, limits: Limits, quality_static: bool) -> None:
        all_urls: list[UrlFinding] = []
        seen: set[str] = set()
        for item in extracted.urls:
            if not item.normalized or item.normalized in seen:
                continue
            seen.add(item.normalized)
            all_urls.append(item)
        hidden_redirect = any(item.code == "HIDDEN_REDIRECT" for item in extracted.evidence)
        ranked: list[tuple[int, int, UrlFinding]] = []
        for index, item in enumerate(all_urls):
            priority = _network_candidate_priority(item, hidden_redirect)
            if priority is not None:
                ranked.append((priority, -index, item))
        ranked.sort(reverse=True, key=lambda row: (row[0], row[1]))
        # Fetching ten personalised links through the same redirector adds risk
        # but almost no information. One candidate per registered domain is enough.
        candidates: list[UrlFinding] = []
        sites: set[str] = set()
        for _priority, _index, item in ranked:
            site = item.registered_domain or item.host or item.normalized
            if site in sites:
                continue
            sites.add(site)
            candidates.append(item)
        fetch_limit = 5 if network == "http" else 2
        report.configuration["network_urls_total"] = len(all_urls)
        report.configuration["network_candidates"] = len(candidates)
        report.configuration["network_ignored_resources"] = len(all_urls) - len(ranked)
        report.configuration["network_fetch_limit"] = fetch_limit
        if not candidates:
            report.configuration["network_analysis_status"] = "NOT_APPLICABLE"
            return
        had_failure = False
        had_success = False
        had_restricted = False
        for item in candidates[:fetch_limit]:
            if "TOKENIZED_URL" in item.flags:
                report.network_activity.append({"url": item.original, "status": "SKIPPED_SENSITIVE_QUERY"})
                had_restricted = True
                continue
            try:
                fetched = safe_http_get(item.normalized, limits) if network == "http" else safe_browser_get(item.normalized, limits, browser_confirmation)
                if "html" in fetched.content_type:
                    remote = extract_html(fetched.body, limits, base_url=fetched.final_url)
                else:
                    remote = extract_any(
                        fetched.body,
                        urlsplit(fetched.final_url).path or "download",
                        fetched.content_type,
                        limits,
                        quality=quality_static,
                    )
                extracted.urls.extend(remote.urls)
                extracted.fingerprints.setdefault("network_pages", []).append({
                    "url": normalize_url(fetched.final_url).redacted,
                    "fingerprints": remote.fingerprints,
                })
                if remote.warnings:
                    had_failure = True
                    report.network_warnings.extend(f"Network page {item.host}: {warning}" for warning in remote.warnings)
                else:
                    had_success = True
                    extracted.attachments.extend(remote.attachments)
                    extracted.evidence.extend(remote.evidence)
                    extracted.text = bounded_text(extracted.text + "\n" + remote.text, limits.max_text_chars)
                    extracted.html_text = bounded_text(extracted.html_text + "\n" + remote.html_text, limits.max_html_chars)
                report.network_activity.append({
                    "url": item.original,
                    "status": ("PARTIAL" if remote.warnings else ("FETCHED" if network == "http" else "BROWSER_RENDERED")),
                    "http_status": fetched.status,
                    "final_url": normalize_url(fetched.final_url).redacted,
                    "redirect_chain": fetched.chain,
                })
            except Exception as exc:
                had_failure = True
                report.network_activity.append({"url": item.original, "status": "FAILED", "error": type(exc).__name__})
                report.network_warnings.append(f"Network analysis failed for {item.host or 'URL'}: {type(exc).__name__}")
        if had_failure:
            network_status = "PARTIAL"
        elif len(candidates) > fetch_limit:
            network_status = "LIMITED"
        elif had_restricted and not had_success:
            network_status = "RESTRICTED"
        else:
            network_status = "COMPLETE"
        report.configuration["network_analysis_status"] = network_status

    def _arbitrate(self, report: AnalysisReport) -> Verdict:
        codes = {e.code for e in report.reason_codes}
        blocking = self.rules["blocking"]
        exact = bool(codes.intersection(blocking["exact_ioc_codes"]))
        if exact:
            return Verdict.PHISHING
        composite = (
            bool(codes.intersection(blocking["intent_codes"]))
            and bool(codes.intersection(blocking["recipient_codes"]))
            and bool(codes.intersection(blocking["mismatch_codes"]))
        )
        if composite and report.analysis_status == AnalysisStatus.COMPLETE:
            return Verdict.PHISHING
        single_high = codes.intersection(self.rules["suspicious"]["single_high_codes"])
        medium_groups = {
            e.independent_group for e in report.reason_codes
            if e.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL} and e.independent_group not in {"model", "status"}
        }
        if single_high or len(medium_groups) >= self.rules["suspicious"]["minimum_medium_independent_groups"] or composite:
            return Verdict.SUSPICIOUS
        return Verdict.NOT_DETECTED


def _deduplicate_urls(urls: list[UrlFinding]) -> list[UrlFinding]:
    result: list[UrlFinding] = []
    seen: set[tuple] = set()
    for item in urls:
        key = (item.normalized, item.source, item.displayed_text)
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result


def _network_candidate_priority(item: UrlFinding, hidden_redirect: bool) -> int | None:
    """Return a navigation priority or None for a passive page resource."""
    source = item.source or ""
    try:
        path = urlsplit(item.normalized or "").path.casefold()
    except ValueError:
        return None
    if any(path.endswith(suffix) for suffix in _STATIC_RESOURCE_SUFFIXES):
        return None
    if source.startswith("qr:"):
        priority = 120
    elif source == "meta-refresh":
        priority = 115
    elif source in {"html:a:href", "html:area:href"} or (source == "html:href" and item.displayed_text):
        priority = 100
    elif source in {"html:iframe:src", "html:frame:src"}:
        priority = 95
    elif source == "javascript" and hidden_redirect:
        priority = 90
    elif source == "text" or source.startswith(("pdf:", "office:")):
        priority = 80
    else:
        return None
    if item.displayed_text:
        priority += 5
    if {"URL_SHORTENER", "MIXED_SCRIPT_HOST", "IP_LITERAL", "USERINFO_IN_URL"}.intersection(item.flags):
        priority += 10
    return priority


def _deduplicate_evidence(evidence: list[Evidence]) -> list[Evidence]:
    result: list[Evidence] = []
    seen: set[tuple] = set()
    for item in evidence:
        key = (item.code, json.dumps(item.details, ensure_ascii=False, sort_keys=True, default=str))
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result
