"""Bounded HTML observations. Every form and signal belongs to one page."""
from __future__ import annotations

import base64
import hashlib
import re
from urllib.parse import urljoin
from urllib.parse import unquote

from lxml import etree, html

from .config import Limits
from .models import FormFinding, PageFinding, Severity
from .urltools import extract_urls, normalize_url, same_site, unwrap_url
from .utils import bounded_text, sha256_bytes, simhash64


SECRET_FIELDS = {
    "password": re.compile(r"(?i)(?:password|passwd|passwort|парол|senha|pwd|^pass$)"),
    "otp": re.compile(r"(?i)(?:\botp\b|one.time.code|verification.code|код.{0,15}(?:подтверж|смс|sms)|sms.code|^pin$|пин.код)"),
    "card": re.compile(r"(?i)(?:\bcvv\b|\bcvc\b|card.number|cardnumber|номер.{0,10}карт|cc.number)"),
    "wallet_secret": re.compile(r"(?i)(?:seed|mnemonic|private.?key|сид.?фраз|секретн.{0,10}ключ)"),
    "personal_data": re.compile(r"(?i)(?:snils|снилс|passport|паспорт)"),
}


def decode_script_literals(script: str, cap: int = 1_000_000) -> str:
    """Decode literal encodings only; never evaluate JavaScript."""
    value = script[:cap].replace(r"\/", "/")
    value = re.sub(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))", lambda m: chr(int(m.group(1) or m.group(2), 16)), value)
    extra = []
    for match in re.finditer(r"String\.fromCharCode\s*\(\s*([\d\s,xXa-fA-F]+)\)", value):
        numbers = match.group(1).split(',')
        if len(numbers) <= 4096:
            try:
                extra.append(''.join(chr(int(v.strip(), 16 if v.strip().lower().startswith('0x') else 10)) for v in numbers))
            except (ValueError, OverflowError):
                pass
    for match in re.finditer(r"(?:decodeURI|decodeURIComponent)\s*\(\s*['\"]([^'\"]{1,10000})['\"]\s*\)", value):
        extra.append(unquote(match.group(1)))
    for match in re.finditer(r"\batob\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)", value):
        try:
            decoded = base64.b64decode(match.group(1), validate=True).decode("utf-8", "replace")
            extra.append(decoded[:cap // 4])
        except (ValueError, UnicodeError):
            pass
        if sum(map(len, extra)) >= cap:
            break
    return (value + "\n" + "\n".join(extra))[:cap]


def collector_calls(script):
    """Bound complete calls, so a field read cannot attach to unrelated fetch."""
    starts = list(re.finditer(r"(?is)(?:fetch|\$\.post|axios\.post)\s*\(\s*['\"]([^'\"]+)['\"]", script))[:200]
    for match in starts:
        opening = script.find("(", match.start(), match.end())
        depth, quote, escaped = 0, None, False
        for index in range(opening, min(len(script), opening + 20000)):
            char = script[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in "'\"`":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    yield match.group(1), script[opening:index+1]
                    break


def visible_text(root, identity=False):
    ignored = {"script", "style", "noscript", "template"}
    if identity:
        ignored |= {"a", "button", "footer", "nav"}
    parts = []
    for value in root.xpath(".//text()"):
        node = value.getparent()
        if value.is_tail:
            node = node.getparent()
        if node is None:
            continue
        ancestors = [node, *node.iterancestors()]
        if any(a.tag in ignored or (a.tag == 'dialog' and a.get('open') is None) or a.get("hidden") is not None or re.search(r"(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden)", a.get("style", "")) for a in ancestors):
            continue
        parts.append(str(value))
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


def extract_html(data: bytes, limits: Limits, base_url: str | None = None, encoding: str | None = None, _embedded_depth: int = 0):
    from .extractors import (Extracted, _append_url, _decode_html, _evidence,
        PASSWORD_LURE, DOCUMENT_LURE, VIEWER_TERMS, REDIRECT_JS, EXFIL_JS,
        OBFUSCATED_JS, GENERIC_LOGIN_TERMS, MAILBOX_LURE, FINANCIAL_LOGIN)

    result = Extracted(kind="html", sha256=sha256_bytes(data), size=len(data))
    decoded = _decode_html(data[:limits.max_input_bytes], encoding)
    if len(data) > limits.max_input_bytes or len(decoded) > limits.max_html_chars:
        result.warnings.append("HTML input limit reached")
        decoded = decoded[:limits.max_html_chars]
    scope = "page:" + hashlib.sha256(((base_url or "") + result.sha256).encode()).hexdigest()[:20]
    result.metadata["scope_id"] = scope
    result.metadata["max_urls"] = limits.max_urls
    parsed_base = normalize_url(base_url) if base_url else None
    page = PageFinding(scope, result.sha256, parsed_base.redacted if parsed_base else None, parsed_base.host if parsed_base else None)
    result.pages.append(page)
    try:
        root = html.fromstring(decoded, parser=html.HTMLParser(recover=True, no_network=True, huge_tree=False))
    except (etree.ParserError, ValueError, LookupError, UnicodeError) as exc:
        result.text = bounded_text(re.sub(r"<[^>]+>", " ", decoded), limits.max_text_chars)
        result.warnings.append(f"HTML recovered as text: {type(exc).__name__}")
        page.complete = False
        for url in extract_urls(decoded)[:limits.max_urls]:
            _append_url(result, url, "html-raw")
        return result

    resolution_base = base_url
    bases = root.xpath("//base[@href]")
    if bases:
        candidate = urljoin(base_url or "", bases[0].get("href", ""))
        try:
            resolution_base = normalize_url(candidate).normalized
        except ValueError:
            pass
    page.title = bounded_text(" ".join(root.xpath("//title/text()")), 240)
    result.text = bounded_text(visible_text(root), limits.max_text_chars)
    page.text = result.text
    identity = " ".join(visible_text(node) for node in root.xpath("//title|//h1|//h2|//form//legend"))
    # Compact sign-in pages frequently keep the logo name in a div rather
    # than a heading. News articles and footers should not become identities.
    if len(result.text) < 1200 and re.search(r"(?i)(?:login|sign in|password|парол|войти|уч[её]тн|аккаунт|личн.{0,15}кабинет|登录|邮箱|密码)",identity + " " + result.text) and not re.search(r"(?i)(?:не\s+(?:сообщ|переда)|никогда.{0,30}(?:парол|код)|мошенник|phishing|do not share)", result.text):
        identity += " " + visible_text(root, identity=True)
    page.identity_text = identity
    scripts = decode_script_literals("\n".join(root.xpath("//script/text()") + [v for n in root.iter() for k, v in n.attrib.items() if k.lower().startswith("on")]))
    embedded = []
    original_scripts = '\n'.join(root.xpath('//script/text()'))
    if _embedded_depth < limits.max_recursion_depth:
        # Literal HTML smuggling is recoverable without running attacker code.
        # Only actual write/HTML-assignment expressions qualify; a decoded
        # string in unrelated analytics is not treated as a displayed form.
        expression = r"(?is)(?:document\.write(?:ln)?\s*\(|\.innerHTML\s*=)\s*(?:atob\s*\(\s*['\"]([A-Za-z0-9+/=]{16,})['\"]\s*\)|(?:unescape|decodeURIComponent)\s*\(\s*['\"]([^'\"]{16,})['\"]\s*\))"
        for match in list(re.finditer(expression, original_scripts))[:3]:
            try:
                content = base64.b64decode(match.group(1), validate=True).decode('utf-8', 'replace') if match.group(1) else unquote(match.group(2))
                if len(content) > min(limits.max_html_chars, 250000):
                    result.warnings.append('Embedded HTML literal limit reached')
                    continue
                if re.search(r'(?i)<(?:html|body|form|input|iframe|script|h1)\b', content):
                    recovered = extract_html(content.encode(), limits, base_url, _embedded_depth=_embedded_depth+1)
                    for recovered_page in recovered.pages:
                        recovered_page.identity_source = 'decoded-script'
                    embedded.append(recovered)
            except (ValueError, UnicodeError):
                continue

    for attr in ("href", "src", "action", "formaction", "data", "poster"):
        for node in root.xpath(f"//*[@{attr}]"):
            value = node.get(attr, "").strip()
            absolute = urljoin(resolution_base or "", value)
            if absolute.lower().startswith(("http://", "https://")):
                tag = node.tag.lower()
                if len(page.resources) < 200 and tag in {'img', 'script', 'iframe', 'frame', 'link', 'object', 'embed'}:
                    try:
                        target_url = normalize_url(absolute)
                        role = 'favicon' if tag == 'link' and 'icon' in node.get('rel', '').lower() else 'stylesheet' if tag == 'link' and 'stylesheet' in node.get('rel', '').lower() else tag
                        page.resources.append({'kind': role, 'url': target_url.redacted, 'host': target_url.host, 'external': bool(parsed_base and not same_site(parsed_base.host, target_url.host))})
                    except ValueError:
                        pass
                displayed = " ".join(node.itertext()).strip() if attr == "href" and tag in {"a", "area"} else None
                _append_url(result, absolute, f"html:{tag}:{attr}", displayed)
                target = unwrap_url(absolute)
                if target:
                    _append_url(result, target, "link-wrapper", displayed)
    for url in extract_urls(scripts):
        _append_url(result, url, "javascript")
    # Google published sheets keep their sheet URL in a JS pageUrl literal.
    # Also follow explicit location assignments, rather than all script resources.
    for match in re.finditer(r"(?is)(?:pageUrl\s*:|(?:window\.)?location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\()\s*['\"]([^'\"]+)['\"]", scripts):
        role = "hosted-document" if re.match(r"(?i)pageUrl",match.group(0)) else "javascript-navigation"
        _append_url(result, urljoin(resolution_base or "", match.group(1)), role)
    # Preserve the role of literal encoded navigations, rather than treating
    # their decoded URLs as passive script strings.
    for match in re.finditer(r"(?is)(?:location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\()\s*((?:atob|decodeURI(?:Component)?|String\.fromCharCode)\s*\([^;]{1,10000}?\))", scripts):
        decoded_navigation = decode_script_literals(match.group(1))
        for target in extract_urls(decoded_navigation)[:3]:
            _append_url(result, target, 'javascript-navigation')

    for anchor in root.xpath("//a[@href]"):
        displayed = extract_urls(" ".join(anchor.itertext()))
        if not displayed:
            continue
        try:
            target_raw = urljoin(resolution_base or "", anchor.get("href"))
            shown = normalize_url(displayed[0])
            target = normalize_url(unwrap_url(target_raw) or target_raw)
            if not same_site(shown.host, target.host):
                result.evidence.append(_evidence("DISPLAY_HREF_MISMATCH", Severity.HIGH, "Показанный домен отличается от адреса перехода", "link", displayed=shown.redacted, destination=target.redacted, destination_host=target.host))
        except (ValueError, TypeError):
            pass

    forms = root.xpath("//form")
    # Many phishing kits have input controls and JS handlers without a form tag.
    if root.xpath("//input[not(ancestor::form)]"):
        forms.append(root)
    if len(forms) > limits.max_forms:
        result.warnings.append("Form count limit reached")
    for index, form in enumerate(forms[:limits.max_forms]):
        fields, types, identifiers = [], set(), []
        nodes = form.xpath(".//input|.//textarea|.//select")
        if form is root and root.tag != "form":
            nodes = [n for n in nodes if not list(n.iterancestors("form"))]
        for node in nodes:
            if node.get("disabled") is not None or node.get("readonly") is not None or any(a.tag in {'template','noscript'} or (a.tag == 'dialog' and a.get('open') is None) or a.get('inert') is not None or a.get("hidden") is not None or re.search(r"(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden)", a.get("style", "")) for a in [node, *node.iterancestors()]):
                continue
            if node.get("type", "").lower() in {"hidden", "submit", "button", "checkbox", "radio"}:
                continue
            descriptor = " ".join(filter(None, [node.get("name"), node.get("id"), node.get("placeholder"), node.get("autocomplete"), node.get("type"), *node.xpath("ancestor::label/text()")]))
            matched = {key for key, pattern in SECRET_FIELDS.items() if pattern.search(descriptor)}
            if node.get("type", "").lower() == "password":
                matched.add("password")
            if matched:
                fields.append(bounded_text(descriptor, 120))
                identifiers.extend(filter(None, [node.get("id"), node.get("name")]))
                types.update(matched)
        if not types:
            continue
        action_attr = form.get("action") if form.tag == "form" else None
        action_raw = urljoin(resolution_base or "", action_attr or "") if form.tag == "form" else ""
        action = None
        try:
            action = normalize_url(action_raw)
        except ValueError:
            pass
        native_disabled = bool(re.search(r"(?i)return\s+false|preventDefault\s*\(",form.get("onsubmit", "")))
        observed = bool(action and form.tag == "form" and not native_disabled)
        # Attribute a network call only when it reads this form's controls.
        collectors = [(destination, call) for destination, call in collector_calls(scripts)
            if re.search(r"(?i)(?:FormData\s*\(|\.serialize\s*\(|\.value\b)", call)
            and ((len(forms) == 1 and re.search(r"FormData\s*\(|\.serialize\s*\(", call))
                 or any(re.search(r"['\"]#?" + re.escape(identifier) + r"['\"]", call) for identifier in identifiers))]
        if collectors:
            try:
                action = normalize_url(urljoin(resolution_base or "", collectors[0][0]))
                observed = True
                result.evidence.append(_evidence("SCRIPT_EXFILTRATION", Severity.HIGH, "Скрипт читает поля формы и отправляет их в сетевой обработчик", "recipient", form_index=index, destination=action.redacted, destination_host=action.host))
            except ValueError:
                pass
        finding = FormFinding(f"{scope}:form:{index}", scope, fields, sorted(types), form.get("method", "get").lower(), action.redacted if action else None, action.host if action else None, observed, bool(action and (not parsed_base or not same_site(action.host, parsed_base.host))))
        finding.selector = root.getroottree().getpath(form)
        finding.safe_structure = '<form method="' + ('post' if finding.method == 'post' else 'get') + '">' + ''.join('<input data-sensitive-type="' + typ + '">' for typ in sorted(types)) + '</form>'
        page.forms.append(finding)
        result.evidence.append(_evidence("SENSITIVE_FORM", Severity.HIGH, "Форма запрашивает секрет или персональные данные", "intent", form_index=index, fields=fields, sensitive_types=sorted(types)))
        if action:
            _append_url(result, action.normalized, "form-action")
            if finding.external:
                result.evidence.append(_evidence("EXTERNAL_FORM_ACTION", Severity.HIGH, "Получатель формы находится на другом сайте", "recipient", form_index=index, destination=action.redacted, destination_host=action.host))
        # A submit button can override an otherwise legitimate form action.
        # Keep its recipient tied to the same sensitive controls.
        for override_index, button in enumerate(form.xpath(".//*[@formaction]")):
            if native_disabled or button.get("disabled") is not None:
                continue
            try:
                recipient = normalize_url(urljoin(resolution_base or "",button.get("formaction")))
            except (ValueError,TypeError):
                continue
            external = not parsed_base or not same_site(recipient.host,parsed_base.host)
            page.forms.append(FormFinding(f"{scope}:form:{index}:submit:{override_index}",scope,fields,sorted(types),button.get("formmethod",finding.method),recipient.redacted,recipient.host,True,external))
            _append_url(result,recipient.normalized,"form-action")

    if REDIRECT_JS.search(scripts):
        result.evidence.append(_evidence("HIDDEN_REDIRECT", Severity.MEDIUM, "Обнаружен JavaScript-переход", "redirect"))
    for meta in root.xpath("//meta[@http-equiv]"):
        if meta.get("http-equiv", "").casefold() != "refresh":
            continue
        match = re.search(r"(?i)url\s*=\s*['\"]?([^'\";]+)", meta.get("content", ""))
        if match:
            _append_url(result, urljoin(resolution_base or "", match.group(1)), "meta-refresh")
            result.evidence.append(_evidence("HIDDEN_REDIRECT", Severity.MEDIUM, "Обнаружен meta refresh", "redirect"))
    patterns = [("CREDENTIAL_LURE", PASSWORD_LURE, "Текст побуждает подтвердить или обновить пароль"), ("DOCUMENT_ACCESS_LURE", DOCUMENT_LURE, "Сценарий доступа к документу"), ("MAILBOX_REVIEW_LURE", MAILBOX_LURE, "Предлагается восстановить якобы заблокированную почту"), ("FINANCIAL_LOGIN_LURE", FINANCIAL_LOGIN, "Предлагается вход в банковский кабинет")]
    for code, pattern, summary in patterns:
        if pattern.search(result.text) and result.urls:
            result.evidence.append(_evidence(code, Severity.MEDIUM, summary, "lure"))
    if page.forms and VIEWER_TERMS.search(result.text):
        result.evidence.append(_evidence("FAKE_DOCUMENT_VIEWER", Severity.HIGH, "Просмотр документа совмещён с запросом секрета", "lure"))
    if OBFUSCATED_JS.search(scripts) and GENERIC_LOGIN_TERMS.search(result.text):
        result.evidence.append(_evidence("OBFUSCATED_LURE_SCRIPT", Severity.MEDIUM, "Обфусцированный код в сценарии входа", "evasion"))
    tokens = [f"{n.tag}:{','.join(sorted(n.attrib))}" for n in root.iter() if isinstance(n.tag, str)]
    skeleton = [('<' if event == 'start' else '</') + node.tag + '>' for event, node in etree.iterwalk(root, events=('start', 'end')) if isinstance(node.tag, str)]
    result.fingerprints.update(sha256=result.sha256, dom_sha256=hashlib.sha256('|'.join(tokens).encode()).hexdigest(), dom_simhash64=simhash64(tokens), js_api_simhash64=simhash64(re.findall(r"[A-Za-z_$][\w$]{2,}", scripts)), form_count=len(forms), sensitive_form_count=len(page.forms))
    result.fingerprints.update(dom_structure_sha256=hashlib.sha256(''.join(skeleton).encode()).hexdigest(), dom_structure_simhash64=simhash64(skeleton), dom_nodes=len(tokens), dom_structure_preview=''.join(skeleton)[:2000])
    from .active import script_facts
    result.fingerprints['script_observations'] = script_facts(scripts, 'html-script-and-events')
    result.html_text = bounded_text(decoded, limits.max_html_chars)
    if not page.forms and re.search(r'(?i)^\s*(?:just a moment|attention required|checking your browser|verify.{0,30}(?:human|robot)|ロボット認証|проверка.{0,30}(?:робот|человек)|доступ запрещ[её]н)',page.title):
        result.warnings.append('Access/automation gate encountered; content behind the gate was not inspected')
    if not result.text.strip() and not page.forms and root.xpath('//script'):
        result.warnings.append('No visible page content; JavaScript rendering is required')
    for evidence in result.evidence:
        evidence.scope_id = scope
    page.complete = not result.warnings
    for recovered in embedded:
        result.pages.extend(recovered.pages)
        result.urls.extend(recovered.urls)
        result.evidence.extend(recovered.evidence)
        result.warnings.extend(recovered.warnings)
        result.text = bounded_text(result.text + '\n' + recovered.text, limits.max_text_chars)
        result.fingerprints.setdefault('decoded_html', []).append({'sha256':recovered.sha256, 'depth':_embedded_depth+1, 'executed':False})
        result.evidence.append(_evidence('HTML_SMUGGLING_RECOVERED', Severity.INFO, 'Восстановлена HTML-страница из буквального кодирования без выполнения скрипта', 'evasion', sha256=recovered.sha256, blocking=False))
    return result
