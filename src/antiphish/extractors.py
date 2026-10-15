from __future__ import annotations

import base64
import email
import hashlib
import html as html_module
import io
import json
import re
import zipfile
from contextvars import ContextVar
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from lxml import etree, html
from PIL import Image

from .config import Limits
from .models import AttachmentFinding, Evidence, PageFinding, Severity, UrlFinding
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
_EXTRACTED_BYTES = ContextVar("antiphish_extracted_bytes", default=None)


@dataclass(slots=True)
class Extracted:
    kind: str
    sha256: str
    size: int
    text: str = ""
    html_text: str = ""
    urls: list[UrlFinding] = field(default_factory=list)
    pages: list[PageFinding] = field(default_factory=list)
    attachments: list[AttachmentFinding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    fingerprints: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def _evidence(code: str, severity: Severity, summary: str, group: str, **details: Any) -> Evidence:
    return Evidence(code=code, severity=severity, summary=summary, details=details, independent_group=group)


def _append_url(result: Extracted, raw: str, source: str, displayed: str | None = None) -> None:
    if len(result.urls) >= result.metadata.get("max_urls", 500):
        if "URL count limit reached" not in result.warnings:
            result.warnings.append("URL count limit reached")
        return
    try:
        item = normalize_url(raw)
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
        navigation_url=item.normalized,
        scope_id=result.metadata.get("scope_id"),
    )
    key = (finding.navigation_url, source, finding.displayed_text)
    if not any((u.navigation_url, u.source, u.displayed_text) == key for u in result.urls):
        result.urls.append(finding)
    risky = {"MIXED_SCRIPT_HOST", "IP_LITERAL", "USERINFO_IN_URL", "NON_STANDARD_PORT"}.intersection(item.flags)
    if risky:
        result.evidence.append(_evidence("URL_OBFUSCATION", Severity.MEDIUM, "Ссылка использует признаки обфускации", "url", url=item.redacted, flags=sorted(risky)))
    if "URL_SHORTENER" in item.flags:
        result.evidence.append(_evidence("URL_SHORTENER", Severity.LOW, "Использован сокращатель ссылок", "url", url=item.redacted))
    if "TOKENIZED_URL" in item.flags and "ACTION_URL" in item.flags:
        result.evidence.append(_evidence("TOKENIZED_ACTION_URL", Severity.MEDIUM, "Ссылка содержит токен действия", "url", url=item.redacted))


def extract_html(data: bytes, limits: Limits, base_url: str | None = None, encoding: str | None = None) -> Extracted:
    from .htmlanalysis import extract_html as parse_html
    return parse_html(data, limits, base_url, encoding)


def _decode_html(data: bytes, declared_encoding: str | None = None) -> str:
    head = data[:4096]
    bom_encodings = []
    if data.startswith(b"\xef\xbb\xbf"):
        bom_encodings.append("utf-8-sig")
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        bom_encodings.append("utf-16")
    charset = re.search(rb"(?i)charset\s*=\s*['\"]?\s*([A-Za-z0-9._-]+)", head)
    candidates = bom_encodings + ([declared_encoding] if declared_encoding else []) + ([charset.group(1).decode("ascii", "ignore")] if charset else []) + ["utf-8", "cp1251", "windows-1252", "latin-1"]
    for encoding in dict.fromkeys(candidates):
        try:
            text = data.decode(encoding)
            # lxml rejects encoding declarations on Unicode input.
            return repair_mojibake(re.sub(r"(?is)^\s*<\?xml[^>]*encoding\s*=\s*['\"][^'\"]+['\"][^>]*\?>", "", text))
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")


def extract_eml(data: bytes, limits: Limits, depth: int = 0, quality: bool = True) -> Extracted:
    result = Extracted(kind="eml", sha256=sha256_bytes(data), size=len(data))
    try:
        # Captured messages sometimes contain CRCRLF. Keep original bytes for
        # hashing, but repair this transport artefact before MIME parsing.
        msg = email.message_from_bytes(data.replace(b"\r\r\n", b"\r\n"), policy=policy.default)
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
    html_parts: list[tuple[bytes, str | None]] = []
    for part in _leaf_parts(msg):
        if part.get_content_type() == "message/rfc822":
            children = part.get_payload()
            if isinstance(children,list):
                for child_message in children:
                    payload = child_message.as_bytes(policy=policy.default)
                    child = extract_any(payload,part.get_filename() or "forwarded.eml","message/rfc822",limits,depth+1,quality=quality)
                    result.attachments.append(AttachmentFinding(part.get_filename() or "forwarded.eml","message/rfc822",len(payload),sha256_bytes(payload),"PARTIAL" if child.warnings else "ANALYZED",sorted({e.code for e in child.evidence})))
                    result.attachments.extend(child.attachments)
                    result.pages.extend(child.pages)
                    result.urls.extend(child.urls)
                    result.evidence.extend(child.evidence)
                    result.warnings.extend(child.warnings)
                    plain_parts.append(child.text)
            continue
        payload = part.get_payload(decode=True) or b""
        if len(payload) > limits.max_attachment_bytes:
            result.warnings.append(f"Part {part.get_filename() or part.get_content_type()} exceeds size limit")
            continue
        ctype = part.get_content_type().lower()
        if ctype in {"application/pkcs7-mime","application/x-pkcs7-mime","application/pgp-encrypted"}:
            result.warnings.append("Encrypted email content cannot be inspected without decryption")
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if ctype == "text/plain" and disposition != "attachment":
            plain_parts.append(_decode_part(payload, part))
        elif ctype == "text/html" and disposition != "attachment":
            html_parts.append((payload, part.get_content_charset()))
        elif filename or disposition == "attachment" or ctype.startswith("image/"):
            name = bounded_text(filename or f"part-{len(result.attachments)+1}", 240)
            child = extract_any(payload, name, ctype, limits, depth + 1, quality=quality)
            finding = AttachmentFinding(name=name, media_type=ctype, size=len(payload), sha256=sha256_bytes(payload), status="PARTIAL" if child.warnings else "ANALYZED", evidence_codes=sorted({e.code for e in child.evidence}))
            result.attachments.append(finding)
            result.urls.extend(child.urls)
            result.pages.extend(child.pages)
            result.evidence.extend(child.evidence)
            result.attachments.extend(child.attachments)
            plain_parts.append(child.text)
            result.warnings.extend(f"Attachment {name}: {w}" for w in child.warnings)
    result.text = bounded_text("\n".join(plain_parts), limits.max_text_chars)
    for body, encoding in html_parts:
        child = extract_html(body, limits, encoding=encoding)
        result.text = bounded_text(result.text + "\n" + child.text, limits.max_text_chars)
        result.html_text = bounded_text(result.html_text + "\n" + child.html_text, limits.max_text_chars)
        result.urls.extend(child.urls)
        result.pages.extend(child.pages)
        result.evidence.extend(child.evidence)
        result.fingerprints.setdefault("html_parts", []).append(child.fingerprints)
        result.warnings.extend(child.warnings)
    for url in extract_urls(result.text)[: limits.max_urls]:
        _append_url(result, url, "text")
    if BEC_TERMS.search((headers.get("subject", "") + " " + result.text)):
        result.evidence.append(_evidence("BEC_PAYMENT_REQUEST", Severity.LOW, "Письмо содержит платёжный или срочный деловой запрос", "intent"))
    result.fingerprints["sha256"] = result.sha256
    return result


def _leaf_parts(message):
    stack = [message]
    while stack:
        part = stack.pop()
        if part.get_content_type() == "message/rfc822" or not part.is_multipart():
            yield part
        else:
            stack.extend(reversed(part.get_payload() or []))


def _decode_part(payload: bytes, part: Message) -> str:
    for charset in (part.get_content_charset(), "utf-8", "cp1251", "latin-1"):
        if charset:
            try:
                return repair_mojibake(payload.decode(charset))
            except (UnicodeDecodeError, LookupError):
                continue
    return payload.decode("utf-8", "replace")


def repair_mojibake(text: str) -> str:
    pattern = re.compile(r"[ÐÑ][^\x00-\x7f]|[РС][\u0400-\u04ff]")
    before = len(pattern.findall(text))
    if before < 5:
        return text
    for encoding in ("latin-1", "cp1251"):
        try:
            repaired = text.encode(encoding).decode("utf-8")
        except (UnicodeError, LookupError):
            continue
        if len(pattern.findall(repaired)) < before / 2:
            return repaired
    # A corrupt block can coexist with correctly encoded Russian text. Repair
    # only Latin-1 runs that round-trip and substantially reduce the markers.
    def repair_run(match):
        value = match.group(0)
        old = len(pattern.findall(value))
        if old < 5:
            return value
        try:
            candidate = value.encode("latin-1").decode("utf-8")
            return candidate if len(pattern.findall(candidate)) < old/2 else value
        except UnicodeError:
            return value
    text = re.sub(r"[\x09\x0a\x0d\x20-\xff]+", repair_run, text)
    # Damage elsewhere in a block can break the whole UTF-8 round trip. Still
    # recover complete Cyrillic words without guessing the missing bytes.
    def repair_sequences(match):
        value = match.group(0)
        try:
            candidate = value.encode("latin-1").decode("utf-8")
            return candidate if re.search(r"[А-Яа-яЁё]",candidate) else value
        except UnicodeError:
            return value
    return re.sub(r"(?:[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3})+",repair_sequences,text)


def _address_domain(value: str) -> str | None:
    address = email.utils.parseaddr(value)[1]
    return address.rsplit("@", 1)[1].lower().rstrip(">") if "@" in address else None


def extract_pdf(data: bytes, limits: Limits, quality: bool = True) -> Extracted:
    result = Extracted(kind="pdf", sha256=sha256_bytes(data), size=len(data))
    try:
        import pymupdf as fitz
        doc = fitz.open(stream=data, filetype="pdf")
        from .active import pdf_actions
        actions, scripts, active_warnings = pdf_actions(doc, limits)
        result.warnings.extend(active_warnings)
        result.fingerprints['pdf_actions'] = actions
        if actions:
            result.evidence.append(_evidence('PDF_ACTIVE_CONTENT', Severity.HIGH, 'PDF содержит структурно обнаруженные действия или вложенные объекты', 'attachment', features=sorted({a['type'] for a in actions}), objects=actions))
        for script in scripts:
            for url in extract_urls(script)[:limits.max_urls]:
                _append_url(result, url, 'pdf:active-action')
        if any(a['type'] in {'Launch', 'ImportData'} or {'secret_field_read', 'network_submission'} <= set(a.get('script', {}).get('features', [])) for a in actions):
            result.evidence.append(_evidence('ACTIVE_PAYLOAD_BEHAVIOR', Severity.HIGH, 'Активный PDF запускает программу или передаёт данные формы', 'attachment', executed=False))
        texts: list[str] = []
        image_count = 0
        for page_index, page in enumerate(doc):
            if page_index >= min(limits.max_pdf_pages, limits.max_pages):
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
            scanned = quality and image_count < limits.max_images_per_document and len(texts[-1].strip()) < 40
            if scanned:
                scale = min(2, 1800 / max(page.rect.width, page.rect.height, 1))
                pixmap = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
                _merge_image(result, pixmap.tobytes("png"), f"pdf:scan-page-{page_index+1}")
                image_count += 1
            embedded_images = page.get_images(full=True)[: max(0, limits.max_images_per_document - image_count)] if quality and not scanned else []
            for image in embedded_images:
                try:
                    blob = doc.extract_image(image[0])["image"]
                    _merge_image(result, blob, f"pdf:image-page-{page_index+1}")
                    image_count += 1
                except Exception:
                    continue
        result.text = bounded_text("\n".join(texts) + "\n" + result.text, limits.max_text_chars)
        result.metadata["page_count"] = doc.page_count
        doc.close()
    except Exception as exc:
        result.warnings.append(f"PDF parsing failed: {type(exc).__name__}")
    for url in extract_urls(result.text)[: limits.max_urls]:
        _append_url(result, url, "pdf:text")
    result.fingerprints["sha256"] = result.sha256
    return result


def extract_office(data: bytes, name: str, limits: Limits) -> Extracted:
    result = Extracted(kind="office", sha256=sha256_bytes(data), size=len(data))
    macro_data = []
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
                        if info.file_size <= limits.max_attachment_bytes:
                            macro_data.append((archive.read(info), info.filename))
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
        if data.startswith(bytes.fromhex('d0cf11e0a1b11ae1')):
            macro_data.append((data, name))
        if b"VBA" in data or b"AutoOpen" in data or b"Document_Open" in data:
            result.evidence.append(_evidence("OFFICE_MACRO", Severity.HIGH, "OLE-документ содержит признаки макроса", "attachment"))
        for url in extract_urls(data.decode("latin-1", "ignore"))[: limits.max_urls]:
            _append_url(result, url, "office:ole")
    if macro_data:
        from .active import vba_facts
        for blob, macro_name in macro_data[:10]:
            observations, scripts, warnings = vba_facts(blob, macro_name)
            result.fingerprints.setdefault('vba_modules', []).extend(observations)
            result.warnings.extend(warnings)
            if observations and not any(e.code == 'OFFICE_MACRO' for e in result.evidence):
                result.evidence.append(_evidence('OFFICE_MACRO', Severity.HIGH, 'Извлечён VBA-код', 'attachment', module_count=len(observations)))
            for code in scripts:
                for url in extract_urls(code)[:limits.max_urls]:
                    _append_url(result, url, 'office:vba')
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
        original = Image.open(io.BytesIO(data))
        if original.width * original.height > 30_000_000:
            result.warnings.append("Image analysis skipped due to pixel limit")
            return
        image = original.convert("RGB")
        result.fingerprints.setdefault("image_phash", []).append(_phash(image))
        if not decode_qr:
            return
        from .ocr import recognize
        text, ocr_status = recognize(image)
        result.metadata.setdefault("ocr", []).append({"source": source, "status": ocr_status})
        if ocr_status in {"UNAVAILABLE", "LIMITED"} or ocr_status.startswith("FAILED:"):
            warning = "Image text inspection: " + ocr_status
            if warning not in result.warnings:
                result.warnings.append(warning)
        if text:
            digest = sha256_bytes(data)
            scope = "image:" + digest[:20]
            page = PageFinding(scope, digest, title=" ".join(text.splitlines()[:3])[:240], text=text, identity_text=text[:1200], identity_source="ocr")
            result.pages.append(page)
            result.text = bounded_text(result.text + "\n" + text, 2_000_000)
            result.evidence.append(Evidence("OCR_TEXT_EXTRACTED", Severity.INFO, "Распознан текст изображения локальной моделью с кириллицей", {"source": source, "characters": len(text), "blocking": False}, independent_group="visual", scope_id=scope))
            old_scope = result.metadata.get("scope_id")
            result.metadata["scope_id"] = scope
            for url in extract_urls(text)[:50]:
                _append_url(result, url, "ocr:text")
            result.metadata["scope_id"] = old_scope
        if image.width * image.height > 30_000_000:
            result.warnings.append("Image QR scan skipped due to pixel limit")
            return
        from .qr import decode
        decoded = decode(image)
        for value in decoded[:20]:
            if value.lower().startswith(("http://", "https://")):
                old_scope = result.metadata.get("scope_id")
                if text:
                    result.metadata["scope_id"] = scope
                _append_url(result, value, f"qr:{source}")
                result.metadata["scope_id"] = old_scope
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
    if len(data) > limits.max_input_bytes:
        raise ValueError("Input exceeds byte limit")
    if depth == 0:
        _EXTRACTED_BYTES.set([len(data)])
    else:
        budget = _EXTRACTED_BYTES.get()
        if budget is not None:
            budget[0] += len(data)
            if budget[0] > limits.max_total_extracted_bytes:
                return Extracted(kind="unknown", sha256=sha256_bytes(data), size=len(data), warnings=["Total extraction byte budget reached"])
    if depth > limits.max_recursion_depth:
        result = Extracted(kind="unknown", sha256=sha256_bytes(data), size=len(data))
        result.warnings.append("Recursion depth limit reached")
        return result
    lower = name.lower()
    ctype = (media_type or "").lower()
    header = data[:65536].replace(b"\r\r\n", b"\r\n").split(b"\n\n", 1)[0]
    if lower.endswith(".eml") or ctype == "message/rfc822" or (re.search(rb"(?im)^From:", header) and re.search(rb"(?im)^(?:Subject|MIME-Version|Received|To):", header)):
        return extract_eml(data, limits, depth, quality=quality)
    if lower.endswith((".html", ".htm")) or "html" in ctype or re.search(rb"(?is)^\s*(?:<!doctype\s+html|<html|<head|<body)", data[:4096]):
        return extract_html(data, limits)
    if lower.endswith(".pdf") or ctype == "application/pdf" or data.startswith(b"%PDF"):
        return extract_pdf(data, limits, quality=quality)
    if lower.endswith((".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm")) or "officedocument" in ctype or "msword" in ctype:
        return extract_office(data, name, limits)
    if data.startswith(b"PK\x03\x04"):
        return extract_archive(data, limits, depth, quality)
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


def extract_archive(data: bytes, limits: Limits, depth: int, quality: bool) -> Extracted:
    result = Extracted(kind="archive", sha256=sha256_bytes(data), size=len(data))
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = [i for i in archive.infolist() if not i.is_dir()]
            total = sum(i.file_size for i in infos)
            compressed = max(1, sum(i.compress_size for i in infos))
            if len(infos) > limits.max_archive_members or total > limits.max_archive_uncompressed_bytes or total / compressed > limits.max_compression_ratio:
                raise ValueError("Archive expansion limit reached")
            for info in infos:
                name = info.filename.replace("\\", "/")
                if info.flag_bits & 1:
                    result.warnings.append("Encrypted archive member cannot be inspected")
                    continue
                if info.file_size > limits.max_attachment_bytes:
                    result.warnings.append("Archive member exceeds size limit")
                    continue
                payload = archive.read(info)
                child = extract_any(payload, name, None, limits, depth + 1, quality=quality)
                result.attachments.append(AttachmentFinding(bounded_text(name,240), child.kind, len(payload), child.sha256, "PARTIAL" if child.warnings else "ANALYZED", sorted({e.code for e in child.evidence})))
                result.attachments.extend(child.attachments)
                result.urls.extend(child.urls)
                result.pages.extend(child.pages)
                result.evidence.extend(child.evidence)
                result.text = bounded_text(result.text + "\n" + child.text, limits.max_text_chars)
                result.warnings.extend(child.warnings)
    except (zipfile.BadZipFile, RuntimeError, ValueError, NotImplementedError) as exc:
        result.warnings.append(f"Archive analysis incomplete: {type(exc).__name__}: {exc}")
    return result
