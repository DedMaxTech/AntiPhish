from __future__ import annotations

import base64
import email
import hashlib
import html as html_module
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from lxml import etree, html
from PIL import Image

from .config import Limits
from .models import AttachmentFinding, Evidence, Severity, UrlFinding
from .urltools import extract_urls, normalize_url, same_site
from .utils import bounded_text, sha256_bytes, simhash64


SENSITIVE_NAMES = re.compile(
    r"(?i)(pass(?:word)?|парол|login|логин|otp|код.?подтверж|cvv|cvc|card|карт|"
    r"pin|пин|seed|mnemonic|сид.?фраз|private.?key|account|сч[её]т|snils|снилс)"
)
EXFIL_JS = re.compile(
    r"(?is)(fetch\s*\(|XMLHttpRequest|\.send\s*\(|axios\.|navigator\.sendBeacon|"
    r"telegram|api\.telegram|webhook|FormData\s*\()"
)
REDIRECT_JS = re.compile(r"(?is)(?:window\.)?location(?:\.href)?\s*=|location\.replace\s*\(|setTimeout\s*\([^)]*location")
VIEWER_TERMS = re.compile(r"(?i)(?:microsoft|office|sharepoint|onedrive|adobe|pdf|document|документ).{0,50}(?:view|просмотр|открыть|download|скачать)")
BEC_TERMS = re.compile(
    r"(?i)(срочн|немедлен|оплат|плат[её]ж|реквизит|сч[её]т на оплат|перевод|"
    r"банковск.{0,20}(?:детал|реквизит)|urgent|wire transfer|bank details|invoice)"
)
PASSWORD_LURE = re.compile(
    r"(?is)(?:(?:password|парол|passwort|senha).{0,100}(?:expir|истека|verify|confirm|keep|update|renew|продл|подтверд|сохран))|"
    r"(?:(?:verify|confirm|keep|update|renew|подтверд|сохран|обнов).{0,100}(?:password|парол|passwort|senha))"
)
DOCUMENT_LURE = re.compile(
    r"(?is)(?:encrypted|secure|shared|protected|зашифрован|защищ[её]н|предоставлен).{0,80}(?:document|package|file|invoice|документ|файл|сч[её]т)|"
    r"(?:document|package|file|invoice|документ|файл|сч[её]т).{0,80}(?:available|access|view|download|доступ|просмотр|скач)"
)
ANTIBOT_TERMS = re.compile(r"(?i)(captcha|verify you are human|checking your browser|challenge-platform|turnstile|провер(?:ка|ьте).{0,30}человек)")
OBFUSCATED_JS = re.compile(r"(?i)(?:atob\s*\(|eval\s*\(|fromCharCode|unescape\s*\(|_0x[0-9a-f]{3,})")
GENERIC_LOGIN_TERMS = re.compile(r"(?i)(?:login|log in|sign in|password|passwort|senha|войти|парол|verify|confirm|подтверд)")
MAILBOX_LURE = re.compile(r"(?is)(?:message|email|mail|письм).{0,100}(?:blocked|hold|quarantine|restriction|failure|заблок|карантин|приостанов).{0,180}(?:review|resolve|release|move|просмотр|восстанов|разреш)")
FINANCIAL_LOGIN = re.compile(r"(?is)(?:bank|credit union|банк|финанс).{0,250}(?:login|log in|sign in|online banking|личн.{0,15}кабинет|войти)")
AUTH_FAIL = re.compile(r"(?i)\b(?:spf|dkim|dmarc)=(?:fail|softfail|permerror|temperror)\b")


@dataclass(slots=True)
class Extracted:
    kind: str
    sha256: str
    size: int
    text: str = ""
    html_text: str = ""
    urls: list[UrlFinding] = field(default_factory=list)
    attachments: list[AttachmentFinding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    fingerprints: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def _evidence(code: str, severity: Severity, summary: str, group: str, **details: Any) -> Evidence:
    return Evidence(code=code, severity=severity, summary=summary, details=details, independent_group=group)


def _append_url(result: Extracted, raw: str, source: str, displayed: str | None = None) -> None:
    try:
        item = normalize_url(html_module.unescape(raw))
    except (ValueError, UnicodeError):
        return
    finding = UrlFinding(
        original=item.redacted,
        # Reports are safe to persist: token-bearing query values are redacted.
        normalized=item.redacted,
        host=item.host,
        registered_domain=item.registered_domain,
        displayed_text=bounded_text(displayed or "", 200) or None,
        source=source,
        flags=list(item.flags),
    )
    key = (finding.normalized, source, finding.displayed_text)
    if not any((u.normalized, u.source, u.displayed_text) == key for u in result.urls):
        result.urls.append(finding)
    risky = {"MIXED_SCRIPT_HOST", "IP_LITERAL", "USERINFO_IN_URL", "NON_STANDARD_PORT"}.intersection(item.flags)
    if risky:
        result.evidence.append(_evidence("URL_OBFUSCATION", Severity.MEDIUM, "Ссылка использует признаки обфускации", "url", url=item.redacted, flags=sorted(risky)))
    if "URL_SHORTENER" in item.flags:
        result.evidence.append(_evidence("URL_SHORTENER", Severity.LOW, "Использован сокращатель ссылок", "url", url=item.redacted))
    if "TOKENIZED_URL" in item.flags and "ACTION_URL" in item.flags:
        result.evidence.append(_evidence("TOKENIZED_ACTION_URL", Severity.MEDIUM, "Ссылка содержит токен действия", "url", url=item.redacted))


def extract_html(data: bytes, limits: Limits, base_url: str | None = None) -> Extracted:
    result = Extracted(kind="html", sha256=sha256_bytes(data), size=len(data))
    if len(data) > limits.max_input_bytes:
        result.warnings.append("HTML exceeds configured input limit and was truncated")
        data = data[: limits.max_input_bytes]
    decoded = _decode_html(data)
    parser = html.HTMLParser(recover=True, no_network=True, huge_tree=False)
    try:
        root = html.fromstring(decoded, parser=parser, base_url=base_url)
    except (etree.ParserError, ValueError, LookupError, UnicodeError) as exc:
        text = decoded
        result.text = bounded_text(re.sub(r"<[^>]+>", " ", text), limits.max_text_chars)
        result.warnings.append(f"HTML parser recovered as plain text: {type(exc).__name__}")
        for url in extract_urls(text)[: limits.max_urls]:
            _append_url(result, url, "html-raw")
        return result

    for bad in root.xpath("//script|//style|//noscript"):
        if bad.tag != "script":
            bad.drop_tree()
    visible = " ".join(root.xpath("//text()[not(ancestor::script) and not(ancestor::style)]"))
    result.text = bounded_text(re.sub(r"\s+", " ", visible).strip(), limits.max_text_chars)
    scripts = "\n".join(root.xpath("//script/text()"))

    for attr in ("href", "src", "action", "data", "poster"):
        for node in root.xpath(f"//*[@{attr}]")[: limits.max_urls]:
            value = node.get(attr, "").strip()
            if not value:
                continue
            absolute = urljoin(base_url, value) if base_url else value
            if absolute.lower().startswith(("http://", "https://")):
                tag = node.tag.lower() if isinstance(node.tag, str) else "unknown"
                displayed = " ".join(node.itertext()).strip() if attr == "href" and tag in {"a", "area"} else None
                _append_url(result, absolute, f"html:{tag}:{attr}", displayed)

    for url in extract_urls(scripts)[: limits.max_urls]:
        _append_url(result, url, "javascript")

    for anchor in root.xpath("//a[@href]"):
        display_urls = extract_urls(" ".join(anchor.itertext()))
        if not display_urls:
            continue
        try:
            shown = normalize_url(display_urls[0])
            target = normalize_url(urljoin(base_url, anchor.get("href")) if base_url else anchor.get("href"))
            if not same_site(shown.host, target.host):
                result.evidence.append(_evidence(
                    "DISPLAY_HREF_MISMATCH", Severity.HIGH,
                    "Показанный домен ссылки отличается от адреса перехода", "link",
                    displayed=shown.redacted, destination=target.redacted,
                ))
        except (ValueError, TypeError):
            pass

    sensitive_forms = 0
    remote_forms = 0
    for index, form in enumerate(root.xpath("//form")[: limits.max_forms]):
        fields = [x for x in form.xpath(".//input|.//textarea|.//select") if x.get("type", "").lower() not in {"hidden", "submit", "button"}]
        sensitive = []
        for node in fields:
            descriptor = " ".join(filter(None, [node.get("name"), node.get("id"), node.get("placeholder"), node.get("autocomplete"), node.get("type")]))
            if node.get("type", "").lower() == "password" or SENSITIVE_NAMES.search(descriptor):
                sensitive.append(bounded_text(descriptor, 120))
        if not sensitive:
            continue
        sensitive_forms += 1
        action_raw = urljoin(base_url, form.get("action", "")) if base_url else form.get("action", "")
        result.evidence.append(_evidence(
            "SENSITIVE_FORM", Severity.HIGH, "Форма запрашивает чувствительные данные", "intent",
            form_index=index, fields=sensitive[:10], method=form.get("method", "get").lower(),
        ))
        if action_raw.lower().startswith(("http://", "https://")):
            remote_forms += 1
            _append_url(result, action_raw, "form-action")
            try:
                action = normalize_url(action_raw)
                page = normalize_url(base_url) if base_url else None
                if page is None or not same_site(page.host, action.host):
                    result.evidence.append(_evidence(
                        "EXTERNAL_FORM_ACTION", Severity.HIGH,
                        "Чувствительные данные отправляются на внешний домен", "recipient",
                        destination=action.redacted, form_index=index,
                    ))
            except ValueError:
                pass

    # Remote forms without visible fields are common document-delivery lures:
    # the hidden identifiers select a victim and the next stage asks for secrets.
    for form in root.xpath("//form[@action]")[: limits.max_forms]:
        action = urljoin(base_url, form.get("action", "")) if base_url else form.get("action", "")
        if action.lower().startswith(("http://", "https://")) and not any(u.source == "form-action" and u.original.startswith(action.split("?", 1)[0]) for u in result.urls):
            remote_forms += 1
            _append_url(result, action, "form-action")
    if remote_forms:
        result.evidence.append(_evidence("REMOTE_FORM_SUBMISSION", Severity.MEDIUM, "HTML-форма отправляется на абсолютный удалённый URL", "recipient", count=remote_forms))

    if sensitive_forms and EXFIL_JS.search(scripts):
        result.evidence.append(_evidence(
            "SCRIPT_EXFILTRATION", Severity.HIGH,
            "Скрипт формы использует сетевую отправку данных", "recipient",
            api=EXFIL_JS.search(scripts).group(0)[:40],
        ))
    if REDIRECT_JS.search(scripts):
        result.evidence.append(_evidence("HIDDEN_REDIRECT", Severity.MEDIUM, "Обнаружен автоматический JavaScript-редирект", "redirect"))
    for meta in root.xpath("//meta[translate(@http-equiv,'REFSH','refsh')='refresh']"):
        content = meta.get("content", "")
        result.evidence.append(_evidence("HIDDEN_REDIRECT", Severity.MEDIUM, "Обнаружен meta refresh", "redirect", content=bounded_text(content, 200)))
        match = re.search(r"(?i)url\s*=\s*['\"]?([^'\";]+)", content)
        if match:
            _append_url(result, urljoin(base_url, match.group(1)) if base_url else match.group(1), "meta-refresh")

    if sensitive_forms and VIEWER_TERMS.search(result.text):
        result.evidence.append(_evidence(
            "FAKE_DOCUMENT_VIEWER", Severity.HIGH,
            "Страница имитирует просмотр документа и запрашивает секрет", "lure",
        ))
    if PASSWORD_LURE.search(result.text) and result.urls:
        result.evidence.append(_evidence("CREDENTIAL_LURE", Severity.HIGH, "Текст побуждает подтвердить, сохранить или обновить пароль", "lure"))
    if DOCUMENT_LURE.search(result.text):
        result.evidence.append(_evidence("DOCUMENT_ACCESS_LURE", Severity.MEDIUM, "Использован сценарий доступа к защищённому или общему документу", "lure"))
    raw_decoded = decoded
    if ANTIBOT_TERMS.search(raw_decoded) and (EXFIL_JS.search(scripts) or REDIRECT_JS.search(scripts)):
        result.evidence.append(_evidence("ACTIVE_CLOAKING", Severity.HIGH, "Антибот-проверка совмещена с активным сетевым кодом или редиректом", "evasion"))
    if OBFUSCATED_JS.search(scripts) and GENERIC_LOGIN_TERMS.search(raw_decoded) and result.urls:
        result.evidence.append(_evidence("OBFUSCATED_LURE_SCRIPT", Severity.HIGH, "Форма входа или проверки содержит обфусцированный JavaScript", "evasion"))
    if MAILBOX_LURE.search(result.text) and result.urls:
        result.evidence.append(_evidence("MAILBOX_REVIEW_LURE", Severity.HIGH, "Сообщение требует проверить или освободить якобы заблокированную почту", "lure"))
    if root.xpath("//iframe") and GENERIC_LOGIN_TERMS.search(result.text):
        result.evidence.append(_evidence("LOGIN_IFRAME", Severity.HIGH, "Сценарий входа загружается через iframe", "lure"))
    if FINANCIAL_LOGIN.search(result.text) and result.urls:
        result.evidence.append(_evidence("FINANCIAL_LOGIN_LURE", Severity.HIGH, "Неподтверждённая банковская страница предлагает вход", "lure"))

    tag_tokens = []
    for node in root.iter():
        if not isinstance(node.tag, str):
            continue
        tag_tokens.append(f"{node.tag.lower()}:{','.join(sorted(k.lower() for k in node.attrib if not k.lower().startswith('data-')))}")
    structure = "|".join(tag_tokens)
    result.fingerprints.update({
        "sha256": result.sha256,
        "dom_sha256": hashlib.sha256(structure.encode()).hexdigest(),
        "dom_simhash64": simhash64(tag_tokens),
        "js_api_simhash64": simhash64(re.findall(r"[A-Za-z_$][\w$]{2,}", scripts)),
        "form_count": len(root.xpath("//form")),
        "sensitive_form_count": sensitive_forms,
    })
    result.html_text = bounded_text(decoded, limits.max_text_chars)
    return result


def _decode_html(data: bytes) -> str:
    head = data[:4096]
    bom_encodings = []
    if data.startswith(b"\xef\xbb\xbf"):
        bom_encodings.append("utf-8-sig")
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        bom_encodings.append("utf-16")
    charset = re.search(rb"(?i)charset\s*=\s*['\"]?\s*([A-Za-z0-9._-]+)", head)
    candidates = bom_encodings + ([charset.group(1).decode("ascii", "ignore")] if charset else []) + ["utf-8", "cp1251", "windows-1252", "latin-1"]
    for encoding in dict.fromkeys(candidates):
        try:
            text = data.decode(encoding)
            # lxml rejects encoding declarations on Unicode input.
            return re.sub(r"(?is)^\s*<\?xml[^>]*encoding\s*=\s*['\"][^'\"]+['\"][^>]*\?>", "", text)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")


def extract_eml(data: bytes, limits: Limits, depth: int = 0, quality: bool = True) -> Extracted:
    result = Extracted(kind="eml", sha256=sha256_bytes(data), size=len(data))
    try:
        msg = email.message_from_bytes(data, policy=policy.default)
    except Exception as exc:
        result.warnings.append(f"Malformed MIME: {type(exc).__name__}")
        result.text = bounded_text(data.decode("utf-8", "replace"), limits.max_text_chars)
        return result
    headers = {k.lower(): bounded_text(str(v), 1000) for k, v in msg.items()}
    result.metadata["headers"] = {k: v for k, v in headers.items() if k in {"from", "to", "subject", "reply-to", "return-path", "authentication-results", "message-id", "date"}}
    result.metadata["subject"] = headers.get("subject", "")
    from_domain = _address_domain(headers.get("from", ""))
    reply_domain = _address_domain(headers.get("reply-to", ""))
    return_domain = _address_domain(headers.get("return-path", ""))
    result.metadata.update(from_domain=from_domain, reply_to_domain=reply_domain, return_path_domain=return_domain)
    if from_domain and reply_domain and not same_site(from_domain, reply_domain):
        result.evidence.append(_evidence("FROM_REPLYTO_MISMATCH", Severity.MEDIUM, "From и Reply-To относятся к разным доменам", "sender", from_domain=from_domain, reply_to_domain=reply_domain))
    if from_domain and return_domain and not same_site(from_domain, return_domain):
        result.evidence.append(_evidence("FROM_RETURNPATH_MISMATCH", Severity.LOW, "From и Return-Path относятся к разным доменам", "sender", from_domain=from_domain, return_path_domain=return_domain))
    if AUTH_FAIL.search(headers.get("authentication-results", "")):
        result.evidence.append(_evidence("AUTHENTICATION_FAILURE", Severity.MEDIUM, "Заголовки сообщают об ошибке SPF/DKIM/DMARC", "sender", result=bounded_text(headers.get("authentication-results", ""), 500)))

    plain_parts: list[str] = []
    html_parts: list[bytes] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        if len(payload) > limits.max_attachment_bytes:
            result.warnings.append(f"Part {part.get_filename() or part.get_content_type()} exceeds size limit")
            continue
        ctype = part.get_content_type().lower()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if ctype == "text/plain" and disposition != "attachment":
            plain_parts.append(_decode_part(payload, part))
        elif ctype == "text/html" and disposition != "attachment":
            html_parts.append(payload)
        elif filename or disposition == "attachment":
            name = bounded_text(filename or f"part-{len(result.attachments)+1}", 240)
            child = extract_any(payload, name, ctype, limits, depth + 1, quality=quality)
            finding = AttachmentFinding(name=name, media_type=ctype, size=len(payload), sha256=sha256_bytes(payload), status="PARTIAL" if child.warnings else "ANALYZED", evidence_codes=sorted({e.code for e in child.evidence}))
            result.attachments.append(finding)
            result.urls.extend(child.urls)
            result.evidence.extend(child.evidence)
            result.warnings.extend(f"Attachment {name}: {w}" for w in child.warnings)
    result.text = bounded_text("\n".join(plain_parts), limits.max_text_chars)
    for body in html_parts:
        child = extract_html(body, limits)
        result.text = bounded_text(result.text + "\n" + child.text, limits.max_text_chars)
        result.html_text = bounded_text(result.html_text + "\n" + child.html_text, limits.max_text_chars)
        result.urls.extend(child.urls)
        result.evidence.extend(child.evidence)
        result.fingerprints.setdefault("html_parts", []).append(child.fingerprints)
        result.warnings.extend(child.warnings)
    for url in extract_urls(result.text)[: limits.max_urls]:
        _append_url(result, url, "text")
    if BEC_TERMS.search((headers.get("subject", "") + " " + result.text)):
        result.evidence.append(_evidence("BEC_PAYMENT_REQUEST", Severity.LOW, "Письмо содержит платёжный или срочный деловой запрос", "intent"))
    result.fingerprints["sha256"] = result.sha256
    return result


def _decode_part(payload: bytes, part: Message) -> str:
    for charset in (part.get_content_charset(), "utf-8", "cp1251", "latin-1"):
        if charset:
            try:
                return payload.decode(charset)
            except (UnicodeDecodeError, LookupError):
                continue
    return payload.decode("utf-8", "replace")


def _address_domain(value: str) -> str | None:
    address = email.utils.parseaddr(value)[1]
    return address.rsplit("@", 1)[1].lower().rstrip(">") if "@" in address else None


def extract_pdf(data: bytes, limits: Limits, quality: bool = True) -> Extracted:
    result = Extracted(kind="pdf", sha256=sha256_bytes(data), size=len(data))
    try:
        import fitz
        doc = fitz.open(stream=data, filetype="pdf")
        texts: list[str] = []
        for page_index, page in enumerate(doc):
            if page_index >= limits.max_pages:
                result.warnings.append("PDF page limit reached")
                break
            texts.append(page.get_text("text"))
            for link in page.get_links():
                if link.get("uri"):
                    _append_url(result, link["uri"], f"pdf:page-{page_index+1}")
            widgets = list(page.widgets() or [])
            sensitive_widgets = []
            for widget in widgets:
                descriptor = " ".join(filter(None, [getattr(widget, "field_name", None), getattr(widget, "field_label", None)]))
                if SENSITIVE_NAMES.search(descriptor):
                    sensitive_widgets.append(bounded_text(descriptor, 120))
            if sensitive_widgets:
                result.evidence.append(_evidence("SENSITIVE_FORM", Severity.HIGH, "PDF-форма запрашивает чувствительные данные", "intent", page=page_index + 1, fields=sensitive_widgets[:10]))
            embedded_images = page.get_images(full=True)[: limits.max_images_per_document] if quality else []
            for image in embedded_images:
                try:
                    blob = doc.extract_image(image[0])["image"]
                    _merge_image(result, blob, f"pdf:image-page-{page_index+1}")
                except Exception:
                    continue
        result.text = bounded_text("\n".join(texts), limits.max_text_chars)
        result.metadata["page_count"] = doc.page_count
        doc.close()
    except Exception as exc:
        result.warnings.append(f"PDF parsing failed: {type(exc).__name__}")
    active_patterns = {
        "JavaScript": rb"/JavaScript|/JS\b",
        "Launch": rb"/Launch\b",
        "EmbeddedFile": rb"/EmbeddedFile\b",
        "OpenAction": rb"/OpenAction\b",
    }
    active = [name for name, pattern in active_patterns.items() if re.search(pattern, data)]
    if active:
        result.evidence.append(_evidence("PDF_ACTIVE_CONTENT", Severity.HIGH, "PDF содержит активное или встроенное содержимое", "attachment", features=active))
    for url in extract_urls(result.text)[: limits.max_urls]:
        _append_url(result, url, "pdf:text")
    result.fingerprints["sha256"] = result.sha256
    return result


def extract_office(data: bytes, name: str, limits: Limits) -> Extracted:
    result = Extracted(kind="office", sha256=sha256_bytes(data), size=len(data))
    if data.startswith(b"PK"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                if len(infos) > limits.max_archive_members:
                    raise ValueError("archive member limit exceeded")
                total = sum(i.file_size for i in infos)
                compressed = max(1, sum(i.compress_size for i in infos))
                if total > limits.max_archive_uncompressed_bytes or total / compressed > limits.max_compression_ratio:
                    raise ValueError("unsafe archive expansion ratio")
                texts = []
                macros = []
                external = []
                for info in infos:
                    lower = info.filename.lower()
                    if "vbaproject.bin" in lower:
                        macros.append(info.filename)
                    if lower.endswith((".xml", ".rels")) and info.file_size <= limits.max_xml_bytes:
                        blob = archive.read(info)
                        if b"<!DOCTYPE" in blob.upper() or b"<!ENTITY" in blob.upper():
                            result.warnings.append(f"Unsafe XML declaration ignored in {info.filename}")
                            continue
                        if lower.endswith(".rels"):
                            for target in re.findall(rb'Target=["\'](https?://[^"\']+)', blob, re.I):
                                value = target.decode("utf-8", "replace")
                                external.append(value)
                                _append_url(result, value, f"office:{info.filename}")
                        try:
                            root = etree.fromstring(blob, parser=etree.XMLParser(resolve_entities=False, no_network=True, recover=True, huge_tree=False))
                            texts.extend(t.strip() for t in root.xpath("//text()") if t.strip())
                        except etree.Error:
                            continue
                result.text = bounded_text(" ".join(texts), limits.max_text_chars)
                if macros:
                    result.evidence.append(_evidence("OFFICE_MACRO", Severity.HIGH, "Office-документ содержит VBA-макрос", "attachment", files=macros[:10]))
                if external:
                    result.evidence.append(_evidence("OFFICE_EXTERNAL_RELATIONSHIP", Severity.MEDIUM, "Office-документ содержит внешние отношения", "attachment", count=len(external)))
        except (zipfile.BadZipFile, ValueError, RuntimeError) as exc:
            result.warnings.append(f"OOXML parsing stopped: {exc}")
    else:
        if b"VBA" in data or b"AutoOpen" in data or b"Document_Open" in data:
            result.evidence.append(_evidence("OFFICE_MACRO", Severity.HIGH, "OLE-документ содержит признаки макроса", "attachment"))
        for url in extract_urls(data.decode("latin-1", "ignore"))[: limits.max_urls]:
            _append_url(result, url, "office:ole")
    for url in extract_urls(result.text)[: limits.max_urls]:
        _append_url(result, url, "office:text")
    result.fingerprints["sha256"] = result.sha256
    return result


def extract_image(data: bytes, limits: Limits, quality: bool = True) -> Extracted:
    result = Extracted(kind="image", sha256=sha256_bytes(data), size=len(data))
    _merge_image(result, data, "image", decode_qr=quality)
    result.fingerprints["sha256"] = result.sha256
    return result


def _merge_image(result: Extracted, data: bytes, source: str, decode_qr: bool = True) -> None:
    try:
        image = Image.open(io.BytesIO(data)).convert("RGB")
        result.fingerprints.setdefault("image_phash", []).append(_phash(image))
        if not decode_qr:
            return
        if image.width * image.height > 30_000_000:
            result.warnings.append("Image QR scan skipped due to pixel limit")
            return
        import cv2
        import numpy as np
        array = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        detector = cv2.QRCodeDetector()
        decoded: list[str] = []
        try:
            ok, values, _points, _ = detector.detectAndDecodeMulti(array)
            if ok:
                decoded.extend(v for v in values if v)
        except cv2.error:
            value, _points, _ = detector.detectAndDecode(array)
            if value:
                decoded.append(value)
        for value in decoded[:20]:
            if value.lower().startswith(("http://", "https://")):
                _append_url(result, value, f"qr:{source}")
                result.evidence.append(_evidence("QR_EXTERNAL_DESTINATION", Severity.MEDIUM, "QR-код содержит веб-адрес", "qr", destination=normalize_url(value).redacted))
    except Exception as exc:
        result.warnings.append(f"Image analysis failed: {type(exc).__name__}")


def _phash(image: Image.Image) -> str:
    import numpy as np
    gray = image.convert("L").resize((32, 32))
    pixels = np.asarray(gray, dtype=float)
    # A compact DCT implementation using OpenCV when available.
    try:
        import cv2
        coeff = cv2.dct(pixels.astype("float32"))[:8, :8]
    except Exception:
        coeff = pixels[:8, :8]
    median = float(np.median(coeff[1:]))
    bits = (coeff > median).flatten()
    return f"{sum(int(bit) << index for index, bit in enumerate(bits)):016x}"


def extract_any(data: bytes, name: str, media_type: str | None, limits: Limits, depth: int = 0, quality: bool = True) -> Extracted:
    if depth > limits.max_recursion_depth:
        result = Extracted(kind="unknown", sha256=sha256_bytes(data), size=len(data))
        result.warnings.append("Recursion depth limit reached")
        return result
    lower = name.lower()
    ctype = (media_type or "").lower()
    if lower.endswith(".eml") or ctype == "message/rfc822" or (b"MIME-Version:" in data[:4096] and b"From:" in data[:4096]):
        return extract_eml(data, limits, depth, quality=quality)
    if lower.endswith((".html", ".htm")) or "html" in ctype or re.search(rb"(?is)^\s*(?:<!doctype\s+html|<html|<head|<body)", data[:4096]):
        return extract_html(data, limits)
    if lower.endswith(".pdf") or ctype == "application/pdf" or data.startswith(b"%PDF"):
        return extract_pdf(data, limits, quality=quality)
    if lower.endswith((".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm")) or "officedocument" in ctype or "msword" in ctype:
        return extract_office(data, name, limits)
    if lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff")) or ctype.startswith("image/"):
        return extract_image(data, limits, quality=quality)
    result = Extracted(kind="binary", sha256=sha256_bytes(data), size=len(data))
    if lower.endswith((".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".js", ".jse", ".vbs", ".vbe", ".hta", ".lnk", ".iso", ".img")):
        result.evidence.append(_evidence("DANGEROUS_ATTACHMENT", Severity.HIGH, "Вложение имеет исполняемый или активный тип", "attachment", filename=name))
    decoded = data[: limits.max_text_chars].decode("utf-8", "replace")
    for url in extract_urls(decoded)[: limits.max_urls]:
        _append_url(result, url, "binary-strings")
    result.fingerprints["sha256"] = result.sha256
    return result
