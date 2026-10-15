"""Conservative decisions from scoped, observable facts rather than global flags."""
from __future__ import annotations

import re
from functools import lru_cache

from .brands import load_brands
from .models import Evidence, Severity, Verdict
from .texttools import normalize_russian
from .urltools import normalize_url, unwrap_url


def official_host(host: str | None, domains: list[str]) -> bool:
    # A suffix test against curated full domains avoids trusting a sibling
    # tenant just because both are hosted under the same provider.
    return bool(host and any(host == d or host.endswith("." + d) for d in domains))


def effective_host(url):
    try:
        if url.redirect_chain:
            return normalize_url(url.redirect_chain[-1]).host
        target = unwrap_url(url.navigation_url or url.normalized)
        return normalize_url(target).host if target else url.host
    except ValueError:
        return url.host


def credential_host(host, brand, types):
    """User-controlled cloud documents are not account authentication origins."""
    if "password" in types and host:
        if brand["name"] == "Google":
            return official_host(host, ["accounts.google.com", "accounts.google.ru"])
        if brand["name"] == "GitHub" and official_host(host, ["githubusercontent.com"]):
            return False
        if brand["name"] == "Microsoft" and official_host(host, ["sharepoint.com", "onedrive.com"]):
            return False
    return official_host(host, brand["domains"] + brand.get('authentication_domains', []))


@lru_cache(maxsize=1)
def catalog():
    return [(brand, [re.compile(r"(?<!\w)" + re.escape(a.casefold()) + r"(?!\w)") for a in brand["aliases"] if len(a.strip()) >= 3]) for brand in load_brands()]


def evaluate_pages(report) -> None:
    report.reason_codes[:] = [e for e in report.reason_codes if e.code not in {"PHISHING_FORM_ROUTE","BRAND_FORM_IMPERSONATION","UNVERIFIED_AUTH_COLLECTOR"}]
    for page in report.pages:
        local = [e for e in report.reason_codes if e.scope_id == page.id]
        brands = [b for b, patterns in catalog() if any(p.search(normalize_russian(page.identity_text).casefold()) for p in patterns)]
        page.claimed_brands = [b["name"] for b in brands]
        for form in page.forms:
            secret = bool(set(form.sensitive_types) & {"password", "otp", "card", "wallet_secret"})
            origin_claims = [b for b in brands if not credential_host(page.host, b, form.sensitive_types)]
            claims = [b for b in origin_claims if not credential_host(form.destination_host, b, form.sensitive_types)]
            if not secret:
                if claims and "personal_data" in form.sensitive_types:
                    report.reason_codes.append(Evidence("BRAND_FORM_IMPERSONATION",Severity.HIGH,"Персональные данные запрашиваются от имени бренда вне его доменов",{"form_id":form.id,"brands":[b["name"] for b in claims],"blocking":False},independent_group="route",scope_id=page.id))
                continue
            # Card-network names describe accepted payment methods on millions
            # of legitimate merchant forms; they are not the account identity.
            if set(form.sensitive_types) <= {"card","personal_data"}:
                claims = [b for b in claims if b["name"].casefold() not in {"visa","mastercard","мир"}]
                origin_claims = [b for b in origin_claims if b["name"].casefold() not in {"visa","mastercard","мир"}]
            # Do not assemble one site's password input with another site's
            # footer link or authentication failure in the parent email.
            mismatch = [e for e in local if e.code == "DISPLAY_HREF_MISMATCH" and e.details.get("destination_host") == form.destination_host]
            if page.complete and page.identity_source == "dom" and form.collector_observed and (claims or mismatch):
                details = {"form_id": form.id, "page": page.url, "destination": form.destination, "sensitive_types": form.sensitive_types, "claimed_brands": [b["name"] for b in claims], "proof": "brand-and-collector" if claims else "displayed-identity-and-collector"}
                report.reason_codes.append(Evidence("PHISHING_FORM_ROUTE", Severity.CRITICAL, "Запрос секрета связан с подменой сервиса и получателем данных", details, independent_group="route", scope_id=page.id))
            elif claims:
                report.reason_codes.append(Evidence("BRAND_FORM_IMPERSONATION", Severity.HIGH, "Секрет запрашивается от имени бренда вне его подтверждённых доменов", {"form_id": form.id, "brands": [b["name"] for b in claims]}, independent_group="route", scope_id=page.id))
            elif brands and form.external and not all(official_host(form.destination_host,b["domains"]) for b in brands):
                report.reason_codes.append(Evidence("UNVERIFIED_AUTH_COLLECTOR",Severity.HIGH,"Официальная страница отправляет секрет неподтверждённому внешнему получателю",{"form_id":form.id,"destination":form.destination},independent_group="route",scope_id=page.id))


def arbitrate(report) -> Verdict:
    codes = {e.code for e in report.reason_codes}
    if codes & {"IOC_SHA256_MATCH", "KNOWN_BAD_URL", "PHISHING_FORM_ROUTE"}:
        return Verdict.PHISHING
    if "VISUAL_REWARD_LURE" in codes:
        return Verdict.SUSPICIOUS
    if codes & {"UNVERIFIED_TRANSFER_LURE", "DOCUMENT_IDENTITY_HOSTING_MISMATCH", "ACCOUNT_RECOVERY_ON_USER_HOSTING", "ACTIVE_PAYLOAD_BEHAVIOR", "BRAND_FORM_IMPERSONATION", "UNVERIFIED_AUTH_COLLECTOR", "REPUTATION_URL_MATCH", "CAMPAIGN_TEMPLATE_MATCH", "DANGEROUS_ATTACHMENT", "OFFICE_MACRO", "UNVERIFIED_REWARD_LURE", "UNVERIFIED_INVESTMENT_LURE", "UNVERIFIED_ACCOUNT_LURE", "SECURITY_THREAT_TO_MESSENGER", "REPLY_FOR_REWARD"}:
        return Verdict.SUSPICIOUS
    for page in report.pages:
        local = [e for e in report.reason_codes if e.scope_id == page.id]
        local_codes = {e.code for e in local}
        brands = [b for b, _ in catalog() if b["name"] in page.claimed_brands]
        trusted_origin = bool(page.host and brands and all(official_host(page.host, b["domains"]) for b in brands))
        delegated = bool(page.forms and all(f.destination_host and any(official_host(f.destination_host, b["domains"]) for b in brands) for f in page.forms))
        navigations = [u for u in report.urls if u.scope_id == page.id and u.source in {"html:a:href","link-wrapper","javascript-navigation","meta-refresh"}]
        official_navigation = bool(brands and navigations and not page.forms and all(any(official_host(effective_host(u),b["domains"]) for b in brands) for u in navigations))
        if trusted_origin or delegated or official_navigation:
            continue
        if local_codes & {"MAILBOX_REVIEW_LURE", "FAKE_DOCUMENT_VIEWER"}:
            return Verdict.SUSPICIOUS
        if "CREDENTIAL_LURE" in local_codes and (page.forms or len(page.text) < 1500 or any(re.search(r"(?i)(?:verify|confirm|renew|keep|update|подтверд|продл|обнов).{0,40}(?:password|парол|аккаунт|account|access|доступ)", u.displayed_text or "") for u in navigations)):
            return Verdict.SUSPICIOUS
        if "MAILBOX_LOGIN_IN_CMS_ASSET" in local_codes:
            return Verdict.SUSPICIOUS
        if local_codes & {"DISPLAY_HREF_MISMATCH"} and (page.forms or local_codes & {"HIDDEN_REDIRECT", "URL_OBFUSCATION"}):
            return Verdict.SUSPICIOUS
        if page.forms and any(f.external or "wallet_secret" in f.sensitive_types for f in page.forms):
            return Verdict.SUSPICIOUS
        if {"HIDDEN_REDIRECT", "OBFUSCATED_LURE_SCRIPT"} <= local_codes and (any(set(f.sensitive_types) & {'password','otp','card','wallet_secret'} for f in page.forms) or re.search(r'(?i)(?:password|sign in|log in|login|mailbox|парол|войти|уч[её]тн)',page.identity_text)):
            return Verdict.SUSPICIOUS
    # The model is an additional reviewer. Require a valid factual extraction
    # with evidence, not a lone yes/no response or a normal credential request.
    for result in report.model_evidence:
        facts = result.get("structured_extract") or {}
        if result.get("parse_status") == "OK" and facts.get("impersonation") is True and (facts.get("credential_request") is True or facts.get("payment_change") is True) and facts.get("evidence_spans"):
            return Verdict.SUSPICIOUS
    return Verdict.NOT_DETECTED
