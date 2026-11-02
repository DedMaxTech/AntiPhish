"""Conservative decisions from scoped, observable facts rather than global flags."""
from __future__ import annotations

import re
from functools import lru_cache

from .brands import load_brands
from .models import Evidence, Severity, Verdict
from .texttools import normalize_russian
from .urltools import normalize_url, unwrap_url, auxiliary_link

BLOCKING_CODES=frozenset({'IOC_SHA256_MATCH','KNOWN_BAD_URL','PHISHING_FORM_ROUTE','REVIEWED_PHISHING_SAMPLE','SECRET_TO_MESSAGING_API'})
PAYMENT_NETWORKS={'visa','mastercard','мир','платёжная система мир'}


def _decision(report, verdict, codes=(), scope_id=None):
    selected=set(codes)
    evidence=[e for e in report.reason_codes if e.code in selected and (scope_id is None or e.scope_id==scope_id)]
    report.configuration['decision']={
        'policy':'scoped-evidence-v4','verdict':verdict.value,'model_alone_can_block':False,
        'reasons':[{'code':e.code,'scope_id':e.scope_id,'independent_group':e.independent_group} for e in evidence],
    }
    ai_based='AI_MODEL_REVIEW' in selected or 'MODEL_SUSPICION' in selected
    report.configuration['decision']['ai_based']=ai_based
    participating={name for e in evidence for name in e.details.get('models',[])}
    for result in report.model_evidence:
        if result.get('model') in participating:result['affects_verdict']=ai_based
    return verdict


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
    user_content={'Google':['docs.google.com','drive.google.com','sites.google.com','googleusercontent.com'],
                  'Microsoft':['sharepoint.com','onedrive.com'],
                  'Яндекс':['forms.yandex.ru','disk.yandex.ru','docs.yandex.ru','yadi.sk'],
                  'Mail.ru':['cloud.mail.ru'],'GitHub':['githubusercontent.com','github.io'],'СБИС':['disk.saby.ru']}
    if brand['name']=='Яндекс':
        user_content['Яндекс'] += [prefix+'.'+d for d in brand['domains'] for prefix in ('forms','disk','docs','docviewer')]
    if set(types)&{'password','otp','card','wallet_secret'} and official_host(host,user_content.get(brand['name'],[])):
        return False
    if set(types)&{'password','otp','wallet_secret'} and host:
        if brand["name"] == "Google":
            return official_host(host, ["accounts.google.com", "accounts.google.ru"])
        if brand["name"] == "GitHub" and official_host(host, ["githubusercontent.com"]):
            return False
        if brand["name"] == "Microsoft" and official_host(host, ["sharepoint.com", "onedrive.com"]):
            return False
        if brand['name']=='Яндекс' and official_host(host,['forms.yandex.ru','disk.yandex.ru','docs.yandex.ru','yadi.sk']):
            return False
        if brand['name']=='Mail.ru' and official_host(host,['cloud.mail.ru']):
            return False
    return official_host(host, brand["domains"] + brand.get('authentication_domains', []))


@lru_cache(maxsize=1)
def catalog():
    return [(brand, [re.compile(r"(?<!\w)" + re.escape(a.casefold()) + r"(?!\w)") for a in brand["aliases"] if len(a.strip()) >= 3]) for brand in load_brands()]


def evaluate_pages(report) -> None:
    report.configuration['brand_checks']=[]
    report.reason_codes[:] = [e for e in report.reason_codes if e.code not in {"PHISHING_FORM_ROUTE","BRAND_FORM_IMPERSONATION","UNVERIFIED_AUTH_COLLECTOR","SECRET_TO_MESSAGING_API","VISUAL_BRAND_AUTH_MISMATCH"}]
    for page in report.pages:
        local = [e for e in report.reason_codes if e.scope_id == page.id]
        brands = [b for b, patterns in catalog() if any(p.search(normalize_russian(page.identity_text).casefold()) for p in patterns)]
        page.claimed_brands = [b["name"] for b in brands]
        provider_names=set()
        if official_host(page.host,['docs.google.com']) and re.search(r'(?i)google\s+forms|гугл\s+форм',page.identity_text):provider_names.add('Google')
        if official_host(page.host,['forms.yandex.ru']) and re.search(r'(?i)яндекс[.\s]*форм|yandex[.\s]*forms',page.identity_text):provider_names.add('Яндекс')
        for form in page.forms:
            secret = bool(set(form.sensitive_types) & {"password", "otp", "card", "wallet_secret"})
            from urllib.parse import urlsplit
            destination_path = urlsplit(form.destination or '').path
            messaging_collector = (form.destination_host == 'api.telegram.org' and bool(re.search(r'(?i)/bot[^/]+/(?:sendMessage|sendDocument|sendPhoto)$',destination_path))) or (form.destination_host in {'discord.com','discordapp.com'} and destination_path.startswith('/api/webhooks/'))
            if page.complete and page.identity_source == 'dom' and form.collector_observed and messaging_collector and set(form.sensitive_types) & {'password','otp','wallet_secret'}:
                report.reason_codes.append(Evidence('SECRET_TO_MESSAGING_API',Severity.CRITICAL,
                    'Форма передаёт пароль, код или секрет кошелька в API сообщений',
                    {'form_id':form.id,'page':page.url,'destination':form.destination,'sensitive_types':form.sensitive_types},independent_group='route',scope_id=page.id))
            origin_claims = [b for b in brands if b['name'] not in provider_names and not credential_host(page.host, b, form.sensitive_types)]
            claims = [b for b in origin_claims if not credential_host(form.destination_host, b, form.sensitive_types)]
            # A bank's own login may mention a partner (e.g. Gosuslugi). An
            # additional brand name must not turn that bank's authenticated
            # origin + collector into an impersonation of the partner.
            own_identity = [b for b in brands if credential_host(page.host,b,form.sensitive_types)
                            and credential_host(form.destination_host,b,form.sensitive_types)]
            if own_identity:
                origin_claims,claims=[],[]
            if not secret:
                if claims and "personal_data" in form.sensitive_types:
                    report.reason_codes.append(Evidence("BRAND_FORM_IMPERSONATION",Severity.HIGH,"Персональные данные запрашиваются от имени бренда вне его доменов",{"form_id":form.id,"brands":[b["name"] for b in claims],"blocking":False},independent_group="route",scope_id=page.id))
                continue
            # Card-network names describe accepted payment methods on millions
            # of legitimate merchant forms; they are not the account identity.
            if set(form.sensitive_types) <= {"card","personal_data"}:
                claims = [b for b in claims if b["name"].casefold() not in PAYMENT_NETWORKS]
                origin_claims = [b for b in origin_claims if b["name"].casefold() not in PAYMENT_NETWORKS]
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

    # Visual presence is weaker than an account identity. Only a localized
    # header logo AND a real secret collector outside that brand's origins
    # can create a review warning; geometry alone never blocks an object.
    brands_by_name={b['name']:b for b,_ in catalog()}
    pages={p.id:p for p in report.pages}
    for item in report.model_evidence:
        if item.get('model')!='Local-logo-geometry':continue
        page=pages.get(item.get('image_context',{}).get('scope_id'))
        if not page or page.identity_source not in {'dom','ocr'} or not page.complete:continue
        height=item.get('image_size',[0,0])[1]
        for candidate in item.get('brand_candidates',[]):
            brand=brands_by_name.get(candidate['brand']);roi=candidate.get('roi',[])
            if not brand or brand['name'].casefold() in PAYMENT_NETWORKS or len(roi)!=4 or not height or roi[1]>height*.35:continue
            for form in page.forms:
                types=set(form.sensitive_types)&{'password','otp','wallet_secret'}
                if not types or not form.collector_observed or not form.destination_host:continue
                if credential_host(page.host,brand,form.sensitive_types) or credential_host(form.destination_host,brand,form.sensitive_types):continue
                if any(credential_host(page.host,b,form.sensitive_types) and credential_host(form.destination_host,b,form.sensitive_types) for b,_ in catalog() if b['name'] in page.claimed_brands):continue
                report.reason_codes.append(Evidence('VISUAL_BRAND_AUTH_MISMATCH',Severity.HIGH,
                    'Логотип бренда и форма входа находятся вне его подтверждённых доменов',
                    {'brand':brand['name'],'form_id':form.id,'destination':form.destination,'page':page.url,'visual_match':candidate,
                     'image_artifact':item.get('image_context',{}).get('artifact_id'),'image_role':item.get('image_context',{}).get('image_role'),'blocking':False},
                    independent_group='route',scope_id=page.id))


    proofs={};deduplicated=[]
    for evidence in report.reason_codes:
        if evidence.code!='VISUAL_BRAND_AUTH_MISMATCH':deduplicated.append(evidence);continue
        key=(evidence.scope_id,evidence.details['form_id'],evidence.details['brand'])
        view={'match':evidence.details['visual_match'],'artifact_id':evidence.details.get('image_artifact'),'role':evidence.details.get('image_role')}
        if key in proofs:proofs[key].details['visual_views'].append(view)
        else:
            evidence.details['visual_views']=[view];proofs[key]=evidence;deduplicated.append(evidence)
    report.reason_codes[:]=deduplicated
    # Explain each actual identity/recipient comparison, including successful
    # verification. Mentions on other pages do not become claims on this form.
    for page in report.pages:
        identities={name:['OCR' if page.identity_source=='ocr' else 'DOM'] for name in page.claimed_brands}
        for item in report.model_evidence:
            if item.get('model')!='Local-logo-geometry' or item.get('image_context',{}).get('scope_id')!=page.id:continue
            for candidate in item.get('brand_candidates',[]):
                identities.setdefault(candidate['brand'],[]).append(candidate['method'])
        for name,sources in identities.items():
            brand=brands_by_name.get(name)
            if not brand:continue
            for form in page.forms or [None]:
                types=form.sensitive_types if form else []
                origin=credential_host(page.host,brand,types)
                collector=credential_host(form.destination_host,brand,types) if form else None
                secret=bool(set(types)&{'password','otp','card','wallet_secret'})
                state='verified' if origin and (form is None or collector) else 'foreign_secret_collector' if form and secret and not origin and not collector else 'external_collector' if origin and form and secret and not collector else 'unverified'
                if state=='foreign_secret_collector' and any(b['name'] in page.claimed_brands
                        and credential_host(page.host,b,types) and credential_host(form.destination_host,b,types) for b,_ in catalog()):
                    state='partner_context'
                if not page.complete:state='partial'
                if name=='Google' and official_host(page.host,['docs.google.com']) and re.search(r'(?i)google\s+forms|гугл\s+форм',page.identity_text):state='provider_context'
                if name=='Яндекс' and official_host(page.host,['forms.yandex.ru']) and re.search(r'(?i)яндекс[.\s]*форм|yandex[.\s]*forms',page.identity_text):state='provider_context'
                report.configuration['brand_checks'].append({'scope_id':page.id,'brand':name,'sources':list(dict.fromkeys(sources)),
                    'page':page.url,'form_id':form.id if form else None,'destination':form.destination if form else None,
                    'sensitive_types':types,'origin_verified':origin,'collector_verified':collector,'status':state,
                    'complete':page.complete,'official_domains':brand['domains']})
                if len(report.configuration['brand_checks'])>=100:return


def arbitrate(report) -> Verdict:
    codes = {e.code for e in report.reason_codes}
    if codes & BLOCKING_CODES:
        return _decision(report,Verdict.PHISHING,codes & BLOCKING_CODES)
    from .behaviorrules import REVIEW_CODES
    if codes & REVIEW_CODES:return _decision(report,Verdict.SUSPICIOUS,codes & REVIEW_CODES)
    if 'REVIEWED_MESSAGE_SIMILARITY' in codes:
        return _decision(report,Verdict.SUSPICIOUS,{'REVIEWED_MESSAGE_SIMILARITY'})
    if codes & {"VISUAL_REWARD_LURE",'VISUAL_BRAND_AUTH_MISMATCH','LOOKALIKE_SECRET_FORM'}:
        return _decision(report,Verdict.SUSPICIOUS,codes & {'VISUAL_REWARD_LURE','VISUAL_BRAND_AUTH_MISMATCH','LOOKALIKE_SECRET_FORM'})
    review_codes={"BRANDED_SECRET_INSTRUCTION","UNVERIFIED_TRANSFER_LURE", "DOCUMENT_IDENTITY_HOSTING_MISMATCH", "ACCOUNT_RECOVERY_ON_USER_HOSTING", "ACTIVE_PAYLOAD_BEHAVIOR", "BRAND_FORM_IMPERSONATION", "UNVERIFIED_AUTH_COLLECTOR", "REPUTATION_URL_MATCH", "CAMPAIGN_TEMPLATE_MATCH", "DANGEROUS_ATTACHMENT", "OFFICE_MACRO", "UNVERIFIED_REWARD_LURE", "UNVERIFIED_INVESTMENT_LURE", "UNVERIFIED_ACCOUNT_LURE", "SECURITY_THREAT_TO_MESSENGER", "REPLY_FOR_REWARD"}
    if codes & review_codes:
        return _decision(report,Verdict.SUSPICIOUS,codes & review_codes)
    for page in report.pages:
        local = [e for e in report.reason_codes if e.scope_id == page.id]
        local_codes = {e.code for e in local}
        brands = [b for b, _ in catalog() if b["name"] in page.claimed_brands]
        trusted_origin = bool(page.host and brands and all(official_host(page.host, b["domains"]) for b in brands))
        delegated = bool(page.forms and all(f.destination_host and any(official_host(f.destination_host, b["domains"]) for b in brands) for f in page.forms))
        navigations = [u for u in report.urls if u.scope_id == page.id and u.source in {"html:a:href","link-wrapper","javascript-navigation","meta-refresh"} and not auxiliary_link(u)]
        official_navigation = bool(brands and navigations and not page.forms and all(any(official_host(effective_host(u),b["domains"]) for b in brands) for u in navigations))
        if trusted_origin or delegated or official_navigation:
            continue
        educational = bool(not page.forms
            and re.search(r'(?i)(?:как.{0,50}(?:фишинг|мошенник)|памятка|защита от фишинга|phishing awareness|security awareness)',page.title+' '+page.identity_text[:400])
            and re.search(r'(?i)(?:не\s+(?:сообщайте|передавайте|вводите)|никогда.{0,35}(?:парол|код)|do not share)',page.text)
            and not any(re.search(r'(?i)(?:войти|подтвердить|восстановить|обновить|login|sign in|verify)',u.displayed_text or '') for u in navigations))
        if not educational and local_codes & {"MAILBOX_REVIEW_LURE", "FAKE_DOCUMENT_VIEWER"}:
            return _decision(report,Verdict.SUSPICIOUS,local_codes & {'MAILBOX_REVIEW_LURE','FAKE_DOCUMENT_VIEWER'},page.id)
        if not educational and "CREDENTIAL_LURE" in local_codes and (page.forms or len(page.text) < 1500 or any(re.search(r"(?i)(?:verify|confirm|renew|keep|update|подтверд|продл|обнов).{0,40}(?:password|парол|аккаунт|account|access|доступ)", u.displayed_text or "") for u in navigations)):
            return _decision(report,Verdict.SUSPICIOUS,{'CREDENTIAL_LURE'},page.id)
        if "MAILBOX_LOGIN_IN_CMS_ASSET" in local_codes:
            return _decision(report,Verdict.SUSPICIOUS,{'MAILBOX_LOGIN_IN_CMS_ASSET'},page.id)
        if local_codes & {"DISPLAY_HREF_MISMATCH"} and (page.forms or local_codes & {"HIDDEN_REDIRECT", "URL_OBFUSCATION"}):
            return _decision(report,Verdict.SUSPICIOUS,local_codes & {'DISPLAY_HREF_MISMATCH','SENSITIVE_FORM','HIDDEN_REDIRECT','URL_OBFUSCATION'},page.id)
        if page.forms and any((f.external and set(f.sensitive_types) & {'password','otp','card','wallet_secret'}) or 'wallet_secret' in f.sensitive_types for f in page.forms):
            return _decision(report,Verdict.SUSPICIOUS,local_codes & {'SENSITIVE_FORM','EXTERNAL_FORM_ACTION','REMOTE_FORM_SUBMISSION'},page.id)
        if {"HIDDEN_REDIRECT", "OBFUSCATED_LURE_SCRIPT"} <= local_codes and (any(set(f.sensitive_types) & {'password','otp','card','wallet_secret'} for f in page.forms) or re.search(r'(?i)(?:password|sign in|log in|login|mailbox|парол|войти|уч[её]тн)',page.identity_text)):
            return _decision(report,Verdict.SUSPICIOUS,{'HIDDEN_REDIRECT','OBFUSCATED_LURE_SCRIPT'},page.id)
    # The model is an additional reviewer. Require a valid factual extraction
    # with evidence, not a lone yes/no response or a normal credential request.
    for result in report.model_evidence:
        facts = result.get("structured_extract") or {}
        if result.get("suspicious") is True and result.get("parse_status") == "OK" and facts.get("impersonation") is True and (facts.get("credential_request") is True or facts.get("payment_change") is True) and facts.get("evidence_spans"):
            if facts.get('credential_request') is True and facts.get('payment_change') is not True:
                forms=[(p,f) for p in report.pages for f in p.forms if set(f.sensitive_types)&{'password','otp','card','wallet_secret'}]
                # A semantic hypothesis cannot overturn a complete, verified
                # official authentication route. Independent proof above still wins.
                if forms and all(p.complete and p.identity_source in {'dom','ocr'} and any(
                        b['name'] in p.claimed_brands and credential_host(p.host,b,f.sensitive_types)
                        and credential_host(f.destination_host,b,f.sensitive_types) for b,_ in catalog()) for p,f in forms):
                    continue
            return _decision(report,Verdict.SUSPICIOUS,{'MODEL_SUSPICION'})
    if 'AI_MODEL_REVIEW' in codes:
        from .modelpolicy import verified_login,verified_action
        if not verified_login(report) and not verified_action(report):return _decision(report,Verdict.SUSPICIOUS,{'AI_MODEL_REVIEW'})
    return _decision(report,Verdict.NOT_DETECTED)
