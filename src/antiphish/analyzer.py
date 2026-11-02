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

    def analyze(self, source: str | Path | bytes, *, name: str | None = None, profile: str = "quality", network: str = "offline", browser_confirmation: str | None = None, base_url: str | None = None, fetcher=None, options: dict | None = None) -> AnalysisReport:
        started = time.perf_counter()
        from .ocr import reset_budget
        reset_budget()
        from .active import reset_budget as reset_active_budget
        reset_active_budget()
        from .options import CURRENT, resolve
        token = None
        try:
            components=resolve(profile, options)
            token=CURRENT.set(components)
            report = self._analyze(source,name=name,profile=profile,network=network,browser_confirmation=browser_confirmation,base_url=base_url,fetcher=fetcher,options=components)
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
        finally:
            if token is not None:
                CURRENT.reset(token)

    def _analyze(self, source: str | Path | bytes, *, name: str | None = None, profile: str = "quality", network: str = "offline", browser_confirmation: str | None = None, base_url: str | None = None, fetcher=None, options: dict | None = None) -> AnalysisReport:
        started = time.perf_counter()
        report = AnalysisReport()
        selected_profile = profile if profile in {"fast", "quality", "deep", "custom"} else "quality"
        from .options import enabled
        components=options or {}
        quality_static = any(enabled(k,False) for k in ('ocr','qr','llm','siglip','logo_references','visual_brands','render_local'))
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
        network_limits={key:components[key] for key in ("max_network_pages","max_navigation_depth","max_network_seconds") if key in components}
        if network_limits:
            analysis_limits=replace(analysis_limits,**network_limits)
        report.configuration = {
            "components":components,
            "profile": selected_profile,
            "network_mode": network,
            "stages": [
                "bounded-static-parsing",
                "url-and-form-analysis",
                "exact-ioc-and-brand-consistency",
                *(["embedded-image-and-qr-analysis"] if quality_static else []),
                *(["local-qwen"] if components['llm'] else []),
                *(["experimental-siglip"] if components['siglip'] or components['logo_references'] else []),
                *(["local-laya-decisions"] if components['laya'] else []),
                *(["local-logo-geometry"] if components['visual_brands'] else []),
            ],
            "profile_note": {
                "fast": "Сокращённые лимиты; без QR и изображений, встроенных в PDF",
                "quality": "Полный статический анализ, включая QR и изображения документов",
                "deep": "Quality плюс локальные Laya, Horizon и Qwen",
                "custom": "Выбранные компоненты; правила и проверка TLS остаются активными",
            }[selected_profile],
            "network_scope": "disabled" if network == "offline" else "pending",
            "network_analysis_status": "NOT_REQUESTED" if network == "offline" else "PENDING",
        }
        from .runtime import manifest
        report.configuration['runtime'] = manifest(self.kb.path)
        report.configuration['runtime']['effective_components']=components
        report.configuration['runtime']['text_classifier']['enabled']=bool(components.get('text_model'))
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
                extracted.metadata.setdefault("message_text", extracted.text)
                extracted.metadata["message_scopes"] = set(extracted.metadata.get('message_body_scopes',[p.id for p in extracted.pages]))
            report.timings_ms['extraction'] = round((time.perf_counter() - stage_started) * 1000, 2)
            stage_started = time.perf_counter()
            if network != "offline":
                from .traversal import enrich
                fetch = fetcher or (safe_http_get if network == "http" else lambda u, l: safe_browser_get(u, l, browser_confirmation))
                enrich(extracted, report, fetch, analysis_limits, quality_static, _network_candidate_priority,
                       asset_fetch=fetcher or safe_http_get)
            report.timings_ms['network'] = round((time.perf_counter() - stage_started) * 1000, 2)
        except Exception as exc:
            if network != "offline":
                report.configuration["network_analysis_status"] = "FAILED"
            report.analysis_status = AnalysisStatus.FAILED
            report.warnings.append(f"Fatal analysis error: {type(exc).__name__}: {exc}")
            report.timings_ms["total"] = round((time.perf_counter() - started) * 1000, 2)
            return report

        report.input.update({"detected_type": extracted.kind, "sha256": extracted.sha256 or None})
        report.source_bytes = data if not source_is_url else b''
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

        if enabled("hash_samples") and extracted.sha256:
            ioc = self.kb.lookup_hash(extracted.sha256)
            if ioc and ioc.get("verdict") == "PHISHING":
                confirmed = ioc.get("provenance") != "provider-labelled-phishing-sample"
                report.reason_codes.append(Evidence(
                    code="IOC_SHA256_MATCH" if confirmed else "KNOWN_SAMPLE_MATCH", severity=Severity.CRITICAL if confirmed else Severity.INFO,
                    summary="Совпадение с подтверждённым IOC" if confirmed else "Совпадение с неразмеченным объектом архивного корпуса; блокировка по хешу отключена",
                    details={"sha256": extracted.sha256, "source": ioc["source"], "provenance": ioc["provenance"]}, independent_group="exact-ioc",
                ))
        for attachment in (report.attachments if enabled("hash_samples") else []):
            ioc = self.kb.lookup_hash(attachment.sha256)
            if ioc and ioc.get("verdict") == "PHISHING":
                confirmed = ioc.get("provenance") != "provider-labelled-phishing-sample"
                report.reason_codes.append(Evidence(
                    code="IOC_SHA256_MATCH" if confirmed else "KNOWN_SAMPLE_MATCH", severity=Severity.CRITICAL if confirmed else Severity.INFO,
                    summary="Вложение совпало с подтверждённым IOC" if confirmed else "Вложение совпало с образцом корпуса; требуется анализ поведения",
                    details={"attachment": attachment.name, "sha256": attachment.sha256, "source": ioc["source"], "provenance": ioc["provenance"]}, independent_group="exact-ioc",
                ))
        for url in (report.urls if enabled("url_iocs") else []):
            if url.host and url.normalized:
                ioc = self.kb.lookup_url(url.host, url.navigation_url or url.normalized)
                if ioc:
                    report.reason_codes.append(Evidence(
                        code="KNOWN_BAD_URL", severity=Severity.CRITICAL,
                        summary="URL совпал с действующим подтверждённым IOC",
                        details={"url": url.original, "source": ioc["source"], "expires_at": ioc["expires_at"]}, independent_group="exact-ioc",
                    ))

        from .reputation import status as reputation_status
        report.reputation = reputation_status(self.kb.reputation_path) if enabled("reputation") else {"status":"DISABLED","sources":[]}
        for url, matches in (self.kb.reputation_matches(report.urls) if enabled("reputation") else []):
            provider_switch={'phishing-database':'feed_phishing_database','openphish':'feed_openphish','phishtank':'feed_phishtank'}
            matches=[m for m in matches if enabled(provider_switch.get(m['provider'],'reputation'))]
            if not matches:
                continue
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
        if enabled('visual_brands',False):
            from .visual import match_image
            from .utils import sha256_bytes
            if enabled('render_local',False):
                from .localrender import enrich as render_local
                render_local(extracted,report)
            from .visualpipeline import inspect as inspect_visuals
            visual_evidence,visual_warnings=inspect_visuals(report.pages,ocr=enabled('ocr',False))
            report.model_evidence.extend(visual_evidence)
            report.model_warnings.extend(visual_warnings)

        from .modelinput import message_text as prepare_model_text,sources as model_sources
        text_input=extracted.metadata.get('subject','')+'\n'+prepare_model_text(extracted,report)
        if enabled('laya',False):
            from .layamodel import configured_score as laya_score
            scores,warnings=laya_score(text_input)
            report.model_evidence.extend(scores)
            report.model_warnings.extend(warnings)
        if enabled('text_model'):
            from .textmodel import configured_score
            scores, warnings = configured_score(text_input,force=True)
            report.model_evidence.extend(scores)
            report.model_warnings.extend(warnings)

        if any(enabled(key,False) for key in ("llm","siglip","logo_references")):
            from .policy import evaluate_pages
            evaluate_pages(report)
            facts = [{"scope":p.id,"origin":p.url,"identity":p.claimed_brands,"forms":[{"types":f.sensitive_types,"destination":f.destination,"collector_observed":f.collector_observed} for f in p.forms]} for p in report.pages if p.forms]
            source_texts=model_sources(extracted,report)
            deep_text='\n\n'.join('SOURCE '+s['id']+' ('+s['label']+'):\n'+s['text'] for s in source_texts)
            from .modelinput import links as model_links
            deep_text+='\n\nOBSERVED LINKS (facts, not original quotations):\n'+json.dumps(model_links(report),ensure_ascii=False)[:2000]
            deep_text+='\n\nOBSERVED FORMS (facts, not original quotations):\n'+json.dumps(facts[:4],ensure_ascii=False)[:1600]
            from .utils import sha256_bytes
            visual_page=next((p for p in report.pages if p.id==extracted.metadata.get("visual_image_scope")),None)
            visual_image=data if extracted.kind=='image' and 'data' in locals() else extracted.metadata.get('visual_image')
            if not visual_page and extracted.kind=="image":
                visual_page=next((p for p in report.pages if p.image_bytes),None)
            if not visual_image:
                pictures=[p for p in report.pages if p.image_bytes]
                renders=[(p,v) for p in report.pages for v in p.visual_images if v['role'] in {'mail-render','local-render','pdf-render'}]
                if renders:
                    visual_page,view=max(renders,key=lambda pair:(bool(pair[0].forms),pair[1]['role']=='mail-render',len(pair[0].text)))
                    visual_image=view['bytes']
                elif pictures:
                    visual_page=max(pictures,key=lambda p:(bool(p.claimed_brands),len(p.image_bytes)))
                    visual_image=visual_page.image_bytes
            model_evidence, warnings = optional_deep_analysis(deep_text, image_bytes=visual_image, run_qwen=enabled("llm",False), run_siglip=enabled("siglip",False), run_references=enabled("logo_references",False),source_texts=source_texts)
            if visual_image:
                try:
                    import io
                    from .deep import _model_image
                    preview=io.BytesIO()
                    _model_image(visual_image).save(preview,'PNG')
                    report.model_image=preview.getvalue()
                except Exception as exc:
                    warnings.append('Просмотр изображения модели недоступен: '+type(exc).__name__)
            for item in model_evidence:
                if item.get('status') == 'NO_IMAGE':
                    mode = report.configuration.get('network_mode', network)
                    item['network_mode'] = mode
                    item['unavailable_sources'] = report.network_warnings[:5]
                    if mode == 'browser':
                        item['note'] = ('Browser не получил пригодный снимок страницы, а в письме нет доступного изображения. '
                                        'Если адрес требует входа или вернул ошибку, галерея логотипов не может его проверить. '
                                        'Это пропуск визуальной проверки, а не отсутствие бренда на сайте.')
                    elif mode == 'http':
                        item['note'] = 'HTTP извлекает код страницы, но не создаёт снимок. В письме нет доступного изображения; для визуального анализа выберите Browser или загрузите изображение.'
                    else:
                        item['note'] = 'В исходном файле нет доступного изображения. В офлайн-проверке снимки внешних страниц не создаются.'
                if report.model_image:
                    item["image_context"]={"scope_id":visual_page.id if visual_page else None,"url":visual_page.url if visual_page else None,"title":visual_page.title if visual_page else report.input.get('name'),"artifact_id":sha256_bytes(report.model_image),"preview_note":"Изображение, поданное модели; дальнейший размер задаёт её процессор"}
                    if visual_page:
                        attachment=next((a for a in report.attachments if a.sha256==visual_page.sha256),None)
                        if attachment: item['image_context']['attachment']=attachment.name
            report.model_evidence.extend(model_evidence)
            report.model_warnings.extend(warnings)
            if any(item.get("suspicious") is True for item in model_evidence):
                report.reason_codes.append(Evidence(code="MODEL_SUSPICION", severity=Severity.MEDIUM, summary="Локальная модель выделила подозрительный сценарий; этот сигнал не блокирует", details={"models": [x["model"] for x in model_evidence]}, independent_group="model"))
        elif profile not in {"fast", "quality", "deep", "custom"}:
            report.warnings.append(f"Unknown profile {profile}; quality policy used")

        report.timings_ms['models'] = round((time.perf_counter() - stage_started) * 1000, 2)
        stage_started = time.perf_counter()
        report.configuration['static_analysis_status'] = 'PARTIAL' if report.warnings else 'COMPLETE'
        report.configuration['model_analysis_status'] = 'PARTIAL' if report.model_warnings or any(e.get('parse_status') == 'INVALID_JSON' or e.get('validation_notes') for e in report.model_evidence) else 'COMPLETE' if any(enabled(k,False) for k in ('llm','siglip','logo_references','visual_brands','text_model','laya')) else 'NOT_REQUESTED'
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
        from .behaviorrules import evaluate as evaluate_behaviours
        evaluate_behaviours(extracted,report)
        from .domainidentity import annotate as annotate_domain_identity
        annotate_domain_identity(report)
        from .templates import match_pages
        if enabled("templates"):
            match_pages(report, self.kb.path)
        from .reviews import apply_reviewed_samples
        if enabled("reviewed_samples"):
            apply_reviewed_samples(report, extracted, self.kb.path)
        report.reason_codes = _deduplicate_evidence(report.reason_codes)
        from .modelpolicy import annotate as annotate_models
        annotate_models(report)
        report.verdict = self._arbitrate(report)
        from .contexts import attach_context
        attach_context(report, extracted)
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
    from .navigation import priority
    return priority(item,hidden_redirect)


def _deduplicate_evidence(evidence: list[Evidence]) -> list[Evidence]:
    result: list[Evidence] = []
    seen: set[tuple] = set()
    for item in evidence:
        key = (item.code, item.scope_id, json.dumps(item.details, ensure_ascii=False, sort_keys=True, default=str))
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result
