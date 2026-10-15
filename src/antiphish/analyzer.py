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
from .extractors import Extracted, _append_url, extract_any, extract_html
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

    def analyze(self, source: str | Path | bytes, *, name: str | None = None, profile: str = "quality", network: str = "offline", browser_confirmation: str | None = None, base_url: str | None = None, fetcher=None) -> AnalysisReport:
        started = time.perf_counter()
        from .ocr import reset_budget
        reset_budget()
        from .active import reset_budget as reset_active_budget
        reset_active_budget()
        try:
            report = self._analyze(source,name=name,profile=profile,network=network,browser_confirmation=browser_confirmation,base_url=base_url,fetcher=fetcher)
            from .logging import completed
            completed(report)
            return report
        except Exception as exc:
            # A broken DB/model/parser must produce an explicit failure report
            # rather than leaving the GUI worker stuck or presenting success.
            report = AnalysisReport(analysis_status=AnalysisStatus.FAILED)
            report.configuration.update(profile=profile,network_mode=network,network_analysis_status="FAILED")
            report.warnings.append("Analysis failed: " + type(exc).__name__)
            report.timings_ms["total"] = round((time.perf_counter()-started)*1000,2)
            return report

    def _analyze(self, source: str | Path | bytes, *, name: str | None = None, profile: str = "quality", network: str = "offline", browser_confirmation: str | None = None, base_url: str | None = None, fetcher=None) -> AnalysisReport:
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
        from .runtime import manifest
        report.configuration['runtime'] = manifest(self.kb.path)
        stage_started = time.perf_counter()
        extracted: Extracted
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
                extracted = extract_html(data, analysis_limits, base_url) if base_url else extract_any(data, input_name, media_type, analysis_limits, quality=quality_static)
            else:
                value = str(source)
                if value.lower().startswith(("http://", "https://")):
                    source_is_url = True
                    normalized = normalize_url(value)
                    base_url = normalized.normalized
                    report.input = {"kind": "url", "value": normalized.redacted, "network": network}
                    extracted = Extracted(kind="url", sha256="", size=0)
                    _append_url(extracted, normalized.normalized, "input")
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

            if extracted.kind == "eml":
                extracted.metadata["message_text"] = extracted.text
                extracted.metadata["message_scopes"] = {p.id for p in extracted.pages}
            report.timings_ms['extraction'] = round((time.perf_counter() - stage_started) * 1000, 2)
            stage_started = time.perf_counter()
            if network != "offline":
                from .traversal import enrich
                fetch = fetcher or (safe_http_get if network == "http" else lambda u, l: safe_browser_get(u, l, browser_confirmation))
                enrich(extracted, report, fetch, analysis_limits, quality_static, _network_candidate_priority)
            report.timings_ms['network'] = round((time.perf_counter() - stage_started) * 1000, 2)
        except Exception as exc:
            if network != "offline":
                report.configuration["network_analysis_status"] = "FAILED"
            report.analysis_status = AnalysisStatus.FAILED
            report.warnings.append(f"Fatal analysis error: {type(exc).__name__}: {exc}")
            report.timings_ms["total"] = round((time.perf_counter() - started) * 1000, 2)
            return report

        report.input.update({"detected_type": extracted.kind, "sha256": extracted.sha256 or None})
        stage_started = time.perf_counter()
        report.urls = _deduplicate_urls(extracted.urls)
        report.pages = extracted.pages
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
        # Cross-page brand findings are descriptive. Decisions are evaluated
        # below within each page/form, not from this global host collection.

        if extracted.sha256:
            ioc = self.kb.lookup_hash(extracted.sha256)
            if ioc and ioc.get("verdict") == "PHISHING":
                confirmed = ioc.get("provenance") != "provider-labelled-phishing-sample"
                report.reason_codes.append(Evidence(
                    code="IOC_SHA256_MATCH" if confirmed else "KNOWN_SAMPLE_MATCH", severity=Severity.CRITICAL if confirmed else Severity.INFO,
                    summary="Совпадение с подтверждённым IOC" if confirmed else "Совпадение с неразмеченным объектом архивного корпуса; блокировка по хешу отключена",
                    details={"sha256": extracted.sha256, "source": ioc["source"], "provenance": ioc["provenance"]}, independent_group="exact-ioc",
                ))
        for attachment in report.attachments:
            ioc = self.kb.lookup_hash(attachment.sha256)
            if ioc and ioc.get("verdict") == "PHISHING":
                confirmed = ioc.get("provenance") != "provider-labelled-phishing-sample"
                report.reason_codes.append(Evidence(
                    code="IOC_SHA256_MATCH" if confirmed else "KNOWN_SAMPLE_MATCH", severity=Severity.CRITICAL if confirmed else Severity.INFO,
                    summary="Вложение совпало с подтверждённым IOC" if confirmed else "Вложение совпало с образцом корпуса; требуется анализ поведения",
                    details={"attachment": attachment.name, "sha256": attachment.sha256, "source": ioc["source"], "provenance": ioc["provenance"]}, independent_group="exact-ioc",
                ))
        for url in report.urls:
            if url.host and url.normalized:
                ioc = self.kb.lookup_url(url.host, url.navigation_url or url.normalized)
                if ioc:
                    report.reason_codes.append(Evidence(
                        code="KNOWN_BAD_URL", severity=Severity.CRITICAL,
                        summary="URL совпал с действующим подтверждённым IOC",
                        details={"url": url.original, "source": ioc["source"], "expires_at": ioc["expires_at"]}, independent_group="exact-ioc",
                    ))

        from .reputation import status as reputation_status
        report.reputation = reputation_status(self.kb.reputation_path)
        for url, matches in self.kb.reputation_matches(report.urls):
            verified = any(m["confidence"] == "verified" for m in matches)
            report.reason_codes.append(Evidence(
                "KNOWN_BAD_URL" if verified else "REPUTATION_URL_MATCH", Severity.CRITICAL if verified else Severity.HIGH,
                "Полный URL найден в локальном снимке фишинговой базы",
                {"url": url.original, "sources": matches, "match_type": "exact-full-url"}, independent_group="reputation", scope_id=url.scope_id))

        from .domains import annotate
        try:
            annotate(report, self.kb.path.with_suffix('.domains.sqlite'))
        except Exception as exc:
            # An advisory CSV must never disable the actual detector.
            report.configuration['domain_context'] = {'status':'UNAVAILABLE', 'error':type(exc).__name__, 'verified':False, 'affects_verdict':False}
        report.timings_ms['knowledge_and_brands'] = round((time.perf_counter() - stage_started) * 1000, 2)
        stage_started = time.perf_counter()
        if extracted.kind == 'eml':
            from .textmodel import configured_score
            scores, warnings = configured_score(extracted.metadata.get('subject', '') + '\n' + extracted.metadata.get('message_text', extracted.text))
            report.model_evidence.extend(scores)
            report.model_warnings.extend(warnings)

        if selected_profile == "deep":
            from .policy import evaluate_pages
            evaluate_pages(report)
            facts = [{"scope":p.id,"origin":p.url,"identity":p.claimed_brands,"forms":[{"types":f.sensitive_types,"destination":f.destination,"collector_observed":f.collector_observed} for f in p.forms]} for p in report.pages if p.forms]
            deep_text = "EXTRACTED PAGE FACTS:\n" + json.dumps(facts[:8],ensure_ascii=False)[:4000]
            deep_text += "\nMESSAGE:\n" + extracted.metadata.get("message_text",brand_text)[:4500]
            deep_text += "\nPAGE TEXT:\n" + "\n".join(p.text[:700] for p in report.pages[-4:])
            deep_text += "\nHTML EXCERPT:\n" + extracted.html_text[:1500]
            model_evidence, warnings = optional_deep_analysis(deep_text, image_bytes=data if extracted.kind == "image" and "data" in locals() else extracted.metadata.get("visual_image"))
            report.model_evidence.extend(model_evidence)
            report.model_warnings.extend(warnings)
            if any(item.get("suspicious") is True for item in model_evidence):
                report.reason_codes.append(Evidence(code="MODEL_SUSPICION", severity=Severity.MEDIUM, summary="Локальная модель выделила подозрительный сценарий; этот сигнал не блокирует", details={"models": [x["model"] for x in model_evidence]}, independent_group="model"))
        elif profile not in {"fast", "quality", "deep"}:
            report.warnings.append(f"Unknown profile {profile}; quality policy used")

        report.timings_ms['models'] = round((time.perf_counter() - stage_started) * 1000, 2)
        stage_started = time.perf_counter()
        report.configuration['static_analysis_status'] = 'PARTIAL' if report.warnings else 'COMPLETE'
        report.configuration['model_analysis_status'] = 'PARTIAL' if report.model_warnings or any(e.get('parse_status') == 'INVALID_JSON' for e in report.model_evidence) else 'COMPLETE' if selected_profile == 'deep' else 'NOT_REQUESTED'
        if report.model_evidence and report.configuration['model_analysis_status'] == 'NOT_REQUESTED':
            report.configuration['model_analysis_status'] = 'COMPLETE'

        if report.warnings or report.configuration['network_analysis_status'] in {'FAILED', 'PARTIAL', 'LIMITED', 'RESTRICTED'} or report.configuration['model_analysis_status'] == 'PARTIAL':
            report.analysis_status = AnalysisStatus.PARTIAL
            report.reason_codes.append(Evidence(code="ANALYSIS_INCOMPLETE", severity=Severity.INFO, summary="Часть запрошенного анализа не выполнена полностью", details={"warnings": report.warnings[:20], 'network_status': report.configuration['network_analysis_status'], 'model_warnings': report.model_warnings}, independent_group="status"))

        report.reason_codes = _deduplicate_evidence(report.reason_codes)
        from .policy import evaluate_pages
        evaluate_pages(report)
        from .content import evaluate_message, evaluate_page_scenarios
        evaluate_message(extracted, report)
        evaluate_page_scenarios(report)
        from .templates import match_pages
        match_pages(report, self.kb.path)
        report.verdict = self._arbitrate(report)
        report.timings_ms['decision'] = round((time.perf_counter() - stage_started) * 1000, 2)
        report.timings_ms["total"] = round((time.perf_counter() - started) * 1000, 2)
        return report

    def _arbitrate(self, report: AnalysisReport) -> Verdict:
        from .policy import arbitrate
        return arbitrate(report)


def _deduplicate_urls(urls: list[UrlFinding]) -> list[UrlFinding]:
    result: list[UrlFinding] = []
    seen: set[tuple] = set()
    for item in urls:
        key = (item.navigation_url or item.normalized, item.scope_id, item.source, item.displayed_text)
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
    if source == "hosted-document":
        priority = 160
    elif source in {"input", "link-wrapper"}:
        priority = 125
    elif source == "javascript-navigation":
        priority = 90
    elif source.startswith("qr:"):
        priority = 120
    elif source == "meta-refresh":
        priority = 115
    elif source in {"html:a:href", "html:area:href"} or (source == "html:href" and item.displayed_text):
        priority = 100
    elif source in {"html:iframe:src", "html:frame:src"}:
        priority = 95
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
        key = (item.code, item.scope_id, json.dumps(item.details, ensure_ascii=False, sort_keys=True, default=str))
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result
