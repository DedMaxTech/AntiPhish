"""Bounded client-side sign-in exploration, with ALL traffic blocked by caller."""
from __future__ import annotations

import re
import secrets
import time

from .htmlanalysis import SECRET_FIELDS

_NEXT = re.compile(r"(?i)^(?:войти|вход|далее|продолжить|подтвердить|login|log in|sign in|next|continue|verify|submit|登录|登錄)\b")
_MAIL = re.compile(r"(?i)(?:email|e-mail|mailbox|почт|логин|username|user.name|^login$|^user$|邮箱|郵箱)")


def probe_forms(page, prepare, deadline):
    """Use only synthetic input; no backend-dependent step can succeed here."""
    markers = {}
    nonce = secrets.token_hex(8)
    values = {"email": "antiphish-" + nonce + "@example.invalid", "password": "AntiPhish-" + nonce + "!", "otp": str(secrets.randbelow(900000) + 100000)}
    body, screenshot = page.content().encode("utf-8"), b""
    origin = page.url
    steps = 0
    for step in range(3):
        if time.monotonic() >= deadline or page.url != origin:
            break
        # Only authentication forms, not shopping, payment or arbitrary CTAs.
        forms = page.locator("form")
        containers = [(forms.nth(fi), fi, False) for fi in range(min(forms.count(), 12))]
        if page.locator("input").evaluate_all("els=>els.some(el=>!el.closest('form'))"):
            containers.append((page.locator("body"), "controls", True))
        choices = []
        for form, fi, outside in containers:
            if not form.is_visible():
                continue
            fields = form.locator("input")
            candidates = []
            for ii in range(min(fields.count(), 30)):
                field = fields.nth(ii)
                if outside and field.evaluate("el=>!!el.closest('form')"):
                    continue
                if not field.is_visible() or not field.is_enabled() or field.get_attribute("readonly") is not None:
                    continue
                kind = (field.get_attribute("type") or "text").lower()
                if kind in {"hidden", "submit", "button", "checkbox", "radio", "file"}:
                    continue
                descriptor = " ".join(field.get_attribute(a) or "" for a in ("name", "id", "placeholder", "autocomplete", "type"))
                types = [key for key in ("password", "otp") if SECRET_FIELDS[key].search(descriptor)]
                typ = "password" if kind == "password" else types[0] if types else "email" if kind == "email" or _MAIL.search(descriptor) else None
                if typ:
                    candidates.append((field, typ))
            if not candidates:
                continue
            buttons = form.locator("button,input[type=submit]")
            for bi in range(min(buttons.count(), 8)):
                button = buttons.nth(bi)
                if outside and button.evaluate("el=>!!el.closest('form')"):
                    continue
                label = (button.inner_text() if button.evaluate("el=>el.tagName==='BUTTON'") else button.get_attribute("value") or "").strip()
                if button.is_visible() and button.is_enabled() and (_NEXT.search(label) or not label and (button.get_attribute("type") or "").lower() == "submit"):
                    choices.append((candidates, button, fi))
                    break
        if not choices:
            break
        candidates, button, fi = choices[0]
        identity = page.locator("title,h1,h2,form legend").all_text_contents()
        for _, typ in candidates:
            markers[values[typ]] = typ
        prepare(dict(markers), origin, " ".join(identity)[:1200], str(fi))
        for field, typ in candidates:
            field.fill(values[typ], timeout=1500)
        body = page.content().encode("utf-8")
        try:
            screenshot = page.screenshot(type="png", timeout=1500, animations="disabled")
        except Exception:
            pass
        try:
            button.click(timeout=1500, no_wait_after=True)
            page.wait_for_timeout(200)
        except Exception:
            break
        steps += 1
        if page.url == origin:
            current = page.content().encode("utf-8")
            if current:
                body = current
    return body, screenshot, steps
