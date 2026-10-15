"""Bounded navigation graph: resources and form recipients are never clicked."""
from __future__ import annotations

import heapq
import time
from dataclasses import replace
from urllib.parse import urlsplit

from .extractors import _append_url, extract_any, extract_html
from .urltools import normalize_url, unwrap_url
from .utils import bounded_text
from .models import Evidence, FormFinding, Severity


def enrich(extracted, report, fetch, limits, quality, priority):
    queue, seen, scheduled = [], set(), set()
    sequence = 0
    initial = len(extracted.urls)
    ignored = 0

    def schedule(items, depth, parent):
        nonlocal sequence, ignored
        hidden = any(e.code == "HIDDEN_REDIRECT" for e in extracted.evidence)
        ranked = [(priority(item, hidden),item) for item in items]
        ranked.sort(key=lambda row: -1 if row[0] is None else row[0],reverse=True)
        for rank,item in ranked:
            raw = item.navigation_url or item.normalized
            if rank is None:
                ignored += 1
                continue
            if not raw or raw in scheduled:
                continue
            scheduled.add(raw)
            sequence += 1
            # Finish a high priority route before browsing newsletter links.
            heapq.heappush(queue, (-(rank + depth * 200), sequence, depth, parent, item))

    schedule(list(extracted.urls), 0, "input")
    report.configuration.update(network_urls_total=initial, network_candidates=len(queue), network_ignored_resources=ignored, network_fetch_limit=limits.max_network_pages, network_scope="navigation-graph")
    started, fetched_count = time.monotonic(), 0
    failures, restricted, limited = False, False, False
    while queue:
        if fetched_count >= limits.max_network_pages or time.monotonic() - started >= limits.max_network_seconds:
            limited = True
            break
        _, _, depth, parent, item = heapq.heappop(queue)
        raw = item.navigation_url or item.normalized
        if raw in seen:
            continue
        seen.add(raw)
        if depth > limits.max_navigation_depth:
            limited = True
            continue
        if "TOKENIZED_URL" in item.flags and "ACTION_URL" in item.flags:
            restricted = True
            item.fetch_status = "SKIPPED_ACTION"
            report.network_activity.append({"url": item.original, "status": item.fetch_status, "depth": depth})
            continue
        wrapper_target = unwrap_url(raw)
        if wrapper_target:
            start = len(extracted.urls)
            _append_url(extracted, wrapper_target, "link-wrapper", item.displayed_text)
            report.routes.append({"from": parent, "via": item.original, "to": normalize_url(wrapper_target).redacted, "kind": "decoded-wrapper", "depth": depth})
            schedule(extracted.urls[start:], depth + 1, item.scope_id or parent)
            continue
        fetched_count += 1
        try:
            remaining = max(.01, limits.max_network_seconds - (time.monotonic() - started))
            fetched = fetch(raw, replace(limits, network_timeout_seconds=min(limits.network_timeout_seconds, remaining), max_network_seconds=remaining))
            final = normalize_url(fetched.final_url)
            # Keep the opened URL even if the response is empty, non-HTML or
            # entirely script based: the reputation check still needs it.
            _append_url(extracted, fetched.final_url, "visited-page")
            for hop in fetched.navigation_chain or fetched.chain:
                if "*" not in hop and "[redacted]" not in hop:
                    _append_url(extracted, hop, "http-redirect")
            if "html" in fetched.content_type:
                remote = extract_html(fetched.body, limits, base_url=fetched.final_url,encoding=fetched.charset)
                if remote.pages:
                    page = remote.pages[0]
                    if fetched.screenshot:
                        from .utils import sha256_bytes
                        page.screenshot_sha256 = sha256_bytes(fetched.screenshot)
                    for interaction in fetched.interactions:
                        if interaction.get("page_url") != fetched.final_url or interaction.get("transmitted") is not False or interaction.get("synthetic_only") is not True:
                            continue
                        types = interaction.get("sensitive_types", [])
                        host = interaction.get("destination_host")
                        if not types or not host:
                            continue
                        finding = FormFinding(page.id + ":dynamic:" + str(len(page.forms)), page.id, ["synthetic-probe"], types, interaction["method"], interaction["destination"], host, True, host != page.host)
                        page.forms.append(finding)
                        page.identity_text += " " + interaction.get("identity_text", "")
                        remote.evidence.append(Evidence("DYNAMIC_SECRET_COLLECTOR", Severity.HIGH, "Сайт попытался отправить тестовый секрет; запрос заблокирован", {"form_id": finding.id, "destination": finding.destination, "sensitive_types": types, "synthetic_only": True, "transmitted": False}, independent_group="recipient", scope_id=page.id))
                    if quality and fetched.screenshot:
                        if page.forms or "visual_image" not in extracted.metadata:
                            extracted.metadata["visual_image"] = fetched.screenshot
                        import io
                        from PIL import Image
                        from .ocr import recognize
                        image = Image.open(io.BytesIO(fetched.screenshot))
                        from .qr import decode
                        old_scope = remote.metadata.get('scope_id')
                        remote.metadata['scope_id'] = page.id
                        for value in decode(image):
                            if value.lower().startswith(('https://', 'http://')):
                                _append_url(remote, value, 'qr:browser-viewport')
                                remote.evidence.append(Evidence('QR_EXTERNAL_DESTINATION', Severity.MEDIUM, 'QR на снимке страницы содержит веб-адрес', {'destination': normalize_url(value).redacted}, independent_group='qr', scope_id=page.id))
                        remote.metadata['scope_id'] = old_scope
                        visual_text, visual_status = recognize(image)
                        if visual_text:
                            remote.text = bounded_text(remote.text + "\n" + visual_text, limits.max_text_chars)
                            page.text += "\n" + visual_text
                            # OCR can support review, but never silently replace
                            # a DOM identity used for automatic blocking.
                            from .policy import catalog
                            if not any(p.search(page.identity_text.casefold()) for _, patterns in catalog() for p in patterns):
                                page.identity_text += " " + visual_text[:1200]
                                page.identity_source = "ocr"
                            remote.evidence.append(Evidence("OCR_TEXT_EXTRACTED", Severity.INFO, "Распознан текст снимка страницы", {"source": "browser-viewport", "characters": len(visual_text), "blocking": False}, independent_group="visual", scope_id=page.id))
                        if visual_status not in {"COMPLETE", "TOO_SMALL"}:
                            remote.warnings.append("Browser image text inspection: " + visual_status)
            else:
                remote = extract_any(fetched.body, urlsplit(fetched.final_url).path or "download", fetched.content_type, limits, quality=quality)
            extracted.urls.extend(remote.urls)
            extracted.pages.extend(remote.pages)
            extracted.attachments.extend(remote.attachments)
            extracted.evidence.extend(remote.evidence)
            extracted.text = bounded_text(extracted.text + "\n" + remote.text, limits.max_text_chars)
            extracted.html_text = bounded_text(extracted.html_text + "\n" + remote.html_text, limits.max_html_chars)
            extracted.fingerprints.setdefault("network_pages", []).append({"url": final.redacted, "fingerprints": remote.fingerprints})
            scope = remote.pages[0].id if remote.pages else "object:" + remote.sha256[:20]
            report.routes.append({"from": parent, "via": item.original, "to": scope, "url": final.redacted, "kind": "navigation", "depth": depth, "redirect_chain": fetched.chain})
            item.redirect_chain = fetched.chain
            item.fetch_status = "PARTIAL" if remote.warnings or fetched.warnings else "FETCHED"
            report.network_activity.append({"url": item.original, "status": item.fetch_status, "http_status": fetched.status, "final_url": final.redacted, "redirect_chain": fetched.chain, "depth": depth})
            if remote.warnings or fetched.warnings:
                failures = True
                report.network_warnings.extend(f"Page {final.host}: {w}" for w in remote.warnings + fetched.warnings)
            schedule(remote.urls, depth + 1, scope)
        except Exception as exc:
            failures = True
            item.fetch_status = "FAILED"
            report.network_activity.append({"url": item.original, "status": "FAILED", "error": type(exc).__name__, "depth": depth})
            report.network_warnings.append(f"Page {item.host}: {type(exc).__name__}")
    report.configuration.update(network_pages_fetched=fetched_count, network_urls_discovered=len(extracted.urls), network_analysis_status="PARTIAL" if failures else "LIMITED" if limited else "RESTRICTED" if restricted else "COMPLETE" if fetched_count else "NOT_APPLICABLE")
