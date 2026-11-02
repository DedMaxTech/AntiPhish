"""Russian social-engineering scenarios. Financial words alone are neutral."""
from __future__ import annotations

import re
import unicodedata
import email.utils

from .models import Evidence, Severity
from .policy import catalog, effective_host, official_host, PAYMENT_NETWORKS
from .urltools import normalize_url, unwrap_url, auxiliary_link
from .texttools import normalize_russian

AUTH = re.compile(r"(?is)(?:подтверд|восстанов|разблок|продл|обнов|истека|expire|keep|verify|confirm).{0,70}(?:парол|доступ|аккаунт|уч[её]тн|password|account)|(?:парол|password).{0,70}(?:истека|expire|обнов|keep)")
WIN = re.compile(r"(?is)(?:вы\s+(?:получили|выиграли|победили)|вам.{0,25}(?:выпал|начислен|одобрен)|забирайте.{0,20}бонус|получить\s+(?:свой\s+)?(?:подарок|сюрприз)|готово\s+к\s+выводу|генератор.{0,30}(?:выбрал|определил)|выбран.{0,20}победител|за\s+(?:участие|опрос)|программа.{0,10}поощрения|(?:ваучер|топливо).{0,80}(?:бесплатно|подарок))")
MONEY = re.compile(r"(?i)(?:\d[\d\s.,]{2,}\s*(?:₽|руб)|приз|подар|выигрыш|выплат|бонус|ваучер)")
INVEST = re.compile(r"(?is)(?:инвестиц|пассивн.{0,10}доход|прирост.{0,15}капитал).{0,350}(?:\+?\d+\s*%|\d[\d\s]{3,}\s*(?:руб|₽))|(?:\d+\s*%).{0,40}(?:в\s+день|ежеднев|за\s+сутки)")
THREAT = re.compile(r"(?i)(?:несанкционирован|подозрительн.{0,25}активност|не\s+оформляли\s+доверенност|доверенность.{0,100}(?:снятие|перевод)|аккаунт.{0,40}заблокирован)")
CTA = re.compile(r"(?i)(?:получ|забра|подтверд|войти|вывод|вывест|откр|анкет|опрос|тест|активир|перей|куп|использ|обнов|начать|ответ|зарегистр|заверш|перевод|оплат|password|continue|login|verify|sign|update|preview|review|open|restore|confirm|complete|view)")
REWARD = re.compile(r"(?i)(?:подар|выигр|бонус|вознаграж|ваучер|выплат|гарантирован.{0,30}поддержк)")
REWARD_ACTION = re.compile(r'(?i)\b(?:получить|получите|забрать|заберите|активировать|активируйте|кликните|проверьте|перейдите|нажмите|опрос)\b[^\n.!?]{0,100}')
FINANCE = re.compile(r"(?i)(?:инвестиц|пассивн.{0,10}доход|прирост.{0,15}капитал|доход\s+от|начинайте.{0,15}зарабат)")
ACCOUNT_UPDATE = re.compile(r"(?is)(?:обнов|актуализ|подтверд|восстанов).{0,100}(?:данны|доступ|личн.{0,15}кабинет|уч[её]тн|аккаунт)")
PAYMENT_UPDATE = re.compile(r'(?is)(?:update|verify|confirm|renew).{0,50}(?:payment\s+(?:information|method|details)|billing\s+(?:information|details)|credit\s+card)|(?:плат[её]жн.{0,15}(?:данны|метод)|банковск.{0,15}карт).{0,50}(?:обнов|подтверд)')
ACCOUNT_THREAT = re.compile(r'(?is)(?:mailbox|email|e-mail|account|почт|аккаунт|уч[её]тн).{0,60}(?:restrict|blocked|error|unusual|suspicious|заблок|ошибк|подозрител)|(?:unusual|suspicious|restrict|blocked).{0,60}(?:login|account|mailbox|email)')
ACCOUNT_ACTION = re.compile(r'(?i)(?:login now|log in|validate your identity|verify|this wasn.t me|восстановить доступ|подтвердить личность)')
USER_HOSTING = re.compile(r'(?i)(?:^|\.)(?:ipfs\.io|cloudflare-ipfs\.com|on-fleek\.app|pages\.dev|workers\.dev|github\.io|blogspot\.com|vercel\.app|netlify\.app|web\.app|firebaseapp\.com|duckdns\.org|ddns\.net|hopto\.org|no-ip\.org|ip-ddns\.com)$')
TRANSFER_COMPLETION = re.compile(r'(?is)(?:заверш(?:ите|ить)|подтверд(?:ите|ить)|получ(?:ите|ить)).{0,60}(?:вывод\s+средств|перевод|выплат)|(?:withdrawal|transfer).{0,60}(?:pending|complete|confirm)')
TRANSFER_DETAILS = re.compile(r'(?i)(?:реквизит|данны.{0,15}карт|bank\s+details|account\s+number)')


def trigger_fragments(text, patterns):
    matches=[]
    for role,pattern in patterns:
        from itertools import islice
        for match in islice(pattern.finditer(text),3):
            start,end=match.span()
            while start>0 and text[start-1].isalpha(): start-=1
            while end<len(text) and text[end].isalpha(): end+=1
            matches.append({'text':text[start:end][:300],'role':role})
    return matches[:9]


def evaluate_message(extracted, report):
    if extracted.kind != "eml":
        return
    # NFC + removal of zero width/combining noise makes Russian lures robust
    # without treating IDNs or Cyrillic themselves as malicious.
    text = normalize_russian(extracted.metadata.get("subject", "") + " " + extracted.metadata.get("message_text", extracted.text))
    declaration = normalize_russian(extracted.metadata.get("subject","") + " " + " ".join(p.identity_text for p in extracted.pages if p.id in extracted.metadata.get("message_scopes",set())))
    lead = ' '.join(normalize_russian(extracted.metadata.get('message_text',extracted.text)).split())[:400]
    action_labels = ' '.join(u.displayed_text or '' for u in report.urls if u.source == 'html:a:href')
    if AUTH.search(action_labels) or ACCOUNT_UPDATE.search(action_labels) or PAYMENT_UPDATE.search(action_labels) or re.match(r'(?i)^(?:DocuSign|Dropbox|Adobe)\b',lead):
        declaration += ' '+lead
    brands = [b for b, patterns in catalog() if any(p.search(declaration.casefold()) for p in patterns)]
    sender = extracted.metadata.get("from_domain")
    display_sender = email.utils.parseaddr(extracted.metadata.get("headers",{}).get("from",""))[0]
    if display_sender:
        brands = [b for b, patterns in catalog() if any(p.search((declaration+" "+normalize_russian(display_sender)).casefold()) for p in patterns)]
    scopes = extracted.metadata.get("message_scopes",set())
    # A reward can be written in an attached picture, with its action in the
    # MIME body. Keep this explicit connection instead of mixing all attachment
    # text into the sender's claims or into every classifier input.
    attachment_claims={}
    if REWARD_ACTION.search(text):
        for page in extracted.pages:
            if page.id in scopes or page.identity_source!='ocr' or not page.image_bytes:continue
            if not (WIN.search(page.text) and MONEY.search(page.text)):continue
            for b,patterns in catalog():
                if b['name'].casefold() not in PAYMENT_NETWORKS and any(p.search(page.identity_text.casefold()) for p in patterns):
                    attachment_claims[b['name']]=page.id
                    if b not in brands:brands.append(b)
    visual_claims={}
    for model in report.model_evidence:
        context=model.get('image_context',{})
        if model.get('model')!='Local-logo-geometry' or context.get('scope_id') not in scopes:continue
        for candidate in model.get('brand_candidates',[]):
            if candidate['brand'].casefold() not in PAYMENT_NETWORKS:
                visual_claims.setdefault(candidate['brand'],[]).append({'artifact_id':context.get('artifact_id'),'method':candidate['method'],'roi':candidate.get('roi')})
    known={b['name'] for b in brands}
    brands.extend(b for b,_ in catalog() if b['name'] in visual_claims and b['name'] not in known)
    nav = [u for u in report.urls if (u.scope_id is None or u.scope_id in scopes) and (u.source in {"html:a:href", "link-wrapper", "javascript-navigation", "text", "ocr:text"} or (u.source or "").startswith("qr:")) and "ACTION_URL" not in u.flags]
    candidates = [u for u in nav if not auxiliary_link(u) and (not u.displayed_text or CTA.search(normalize_russian(u.displayed_text)) or ACCOUNT_ACTION.search(normalize_russian(u.displayed_text)))]
    details = {"brands":[b["name"] for b in brands], "from_domain":sender}
    instruction_links=[u for u in report.urls if (u.scope_id is None or u.scope_id in scopes)
                       and u.source in {'text','html:a:href','link-wrapper'}]
    # A long plain-text message may hide the identity and direct secret request
    # after a routine preamble. Do not restrict this proof-of-intent to a title
    # or the first 400 characters, and do not infer it from a model score.
    instruction=re.compile(r'(?i)(?<!\w)(?:введите|укажите|отправьте|пришлите|сообщите|enter|provide|send)\s+[^.!?\n]{0,80}(?:парол\w*|password|(?:код\w*[^.!?\n]{0,30}(?:смс|sms|подтвержден|входа))|(?:cvv|cvc)|(?:seed\s+phrase))')
    for match in list(instruction.finditer(text))[:20]:
        before=text[max(0,match.start()-180):match.start()]
        if re.search(r'(?i)(?:\bне\s*|никогда\s*|do not\s*|never\s*)$',before):continue
        if re.search(r'(?i)мошенник|фишинг|памятк|пример.{0,30}(?:атаки|сообщения)|phishing|scam example',before):continue
        vicinity=text[max(0,match.start()-180):min(len(text),match.end()+150)]
        identity = re.sub(r'(?i)\bhttps?://\S+|[\w.+-]+@[\w.-]+', ' ', vicinity)
        local_brands=[b for b,patterns in catalog() if b['name'].casefold() not in PAYMENT_NETWORKS
                      and any(p.search(identity.casefold()) for p in patterns)]
        if not local_brands:continue
        nearby=[]
        for url in instruction_links:
            if auxiliary_link(url):continue
            needles=[url.navigation_url or url.normalized or url.original,url.displayed_text or '']
            positions=[text.find(normalize_russian(n),max(0,match.start()-200),min(len(text),match.end()+600)) for n in needles if n and len(n)>3]
            if not any(position>=0 for position in positions):continue
            host=effective_host(url)
            from .policy import credential_host
            foreign=[b for b in local_brands if not credential_host(host,b,['password'])]
            if host and foreign:nearby.append((url,foreign))
        if nearby:
            url,foreign=nearby[0]
            report.reason_codes.append(Evidence('BRANDED_SECRET_INSTRUCTION',Severity.HIGH,
                'От имени бренда просят ввести секрет по ссылке вне его доменов',
                {'brands':[b['name'] for b in foreign],'destinations':[url.original],
                 'matched_text':match.group(0),'trigger_matches':[{'text':match.group(0),'role':'secret-request'}],
                 'blocking':False},independent_group='message-scenario',scope_id='message'))
            break
    for brand in brands:
        external = []
        for item in candidates:
            raw = item.navigation_url or item.normalized
            target = unwrap_url(raw) or raw
            if target and not official_host(effective_host(item),brand["domains"]):
                external.append(item)
        if not external:
            continue
        code = None
        if (WIN.search(text) or (REWARD.search(text) and (REWARD_ACTION.search(text) or re.search(r"(?i)(?:опрос|получ|забрат|активир|гарантирован)",text)))) and MONEY.search(text):
            code = "UNVERIFIED_REWARD_LURE"
        elif INVEST.search(text) or (FINANCE.search(text) and MONEY.search(text)):
            code = "UNVERIFIED_INVESTMENT_LURE"
        elif AUTH.search(text) or ACCOUNT_UPDATE.search(text) or PAYMENT_UPDATE.search(text) or (ACCOUNT_THREAT.search(text) and ACCOUNT_ACTION.search(text)):
            code = "UNVERIFIED_ACCOUNT_LURE"
        elif TRANSFER_COMPLETION.search(text) and TRANSFER_DETAILS.search(text) and (re.search(r'(?i)банк|bank',brand['name']) or brand['name'] in {'ВТБ','ПСБ','МКБ'}):
            code = 'UNVERIFIED_TRANSFER_LURE'
        elif re.search(r"(?is)(?:скидк.{0,15}(?:[5-9]\d|100)\s*%).{0,70}(?:весь|любые|ассортимент)|(?:весь|любые|ассортимент).{0,70}(?:скидк.{0,15}(?:[5-9]\d|100)\s*%)", text) and re.search(r"(?i)(?:только\s+(?:сейчас|сегодня)|ограничен|до\s+\d|несколько\s+дней)",text):
            code = "UNVERIFIED_REWARD_LURE"
        if code:
            # Delivery-provider branding in a Forms receipt is not the brand
            # promising the reward. Do not duplicate the same lure for Google.
            if code=='UNVERIFIED_REWARD_LURE' and brand['name'] in {'Google','Microsoft'} and official_host(sender,brand['domains']) and any(b['name'] not in {'Google','Microsoft'} for b in brands):
                continue
            raw_text=extracted.metadata.get('message_text',extracted.text)
            patterns=[('обещание вознаграждения',REWARD),('запрос действия',REWARD_ACTION)] if code=='UNVERIFIED_REWARD_LURE' else [('сценарий',AUTH),('изменение оплаты',PAYMENT_UPDATE),('инвестиции',INVEST),('перевод',TRANSFER_COMPLETION)]
            matches=trigger_fragments(raw_text,patterns)
            explanation=f"В письме используется бренд {brand['name']}; ссылка действия ведёт вне его доменов. Домен отправителя: {sender or 'не установлен'}."
            identity = {"claimed_brand":brand['name'], "sender_domain":sender,
                        "sender_is_official":official_host(sender,brand['domains']),
                        "action_hosts":sorted({effective_host(u) for u in external if effective_host(u)}),
                        "official_domains":brand['domains'],
                        "basis":"visual-and-action-link" if brand['name'] in visual_claims else "ocr-attachment-and-action-link" if brand['name'] in attachment_claims else "text-and-action-link", "visual_sources":visual_claims.get(brand['name'],[]), "attachment_scope":attachment_claims.get(brand['name']), "catalog_is_exhaustive":False}
            report.reason_codes.append(Evidence(code, Severity.HIGH, f"{brand['name']}: ссылка действия ведёт вне известных доменов бренда", {**details,"brand":brand["name"],"identity_comparison":identity,"destinations":[u.original for u in external[:3]],"trigger_matches":matches,"explanation":explanation, "blocking":False}, independent_group="message-scenario", scope_id="message"))
        elif brand['name'] in {'DocuSign', 'Adobe', 'Dropbox'} and re.search(r'(?i)(?:view|preview|review|sign|просмотр|подпис).{0,40}(?:document|pdf|документ)', text) and any(USER_HOSTING.search(effective_host(u) or '') or re.search(r'(?i)/wp-[a-z-]+/',normalize_url(unwrap_url(u.navigation_url or u.normalized) or u.navigation_url or u.normalized).normalized) for u in external):
            report.reason_codes.append(Evidence('DOCUMENT_IDENTITY_HOSTING_MISMATCH', Severity.HIGH, 'Документ заявленного сервиса открывается на пользовательском хостинге', {**details, 'brand': brand['name'], 'destinations': [u.original for u in external[:3]], 'blocking': False}, independent_group='message-scenario', scope_id='message'))
    # Tenant-specific webmail can be targeted without a catalogued brand.
    # Require an actual mailbox identity, a problem notification, an explicit
    # authentication CTA and a public/user-controlled hosting destination.
    if ACCOUNT_THREAT.search(text) and ACCOUNT_ACTION.search(text) and re.search(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}', text, re.I):
        hosted = [u for u in candidates if USER_HOSTING.search(effective_host(u) or '')]
        if hosted:
            report.reason_codes.append(Evidence('ACCOUNT_RECOVERY_ON_USER_HOSTING', Severity.HIGH, 'Восстановление почты предлагается через пользовательский хостинг', {'destinations': [u.original for u in hosted[:3]], 'blocking': False}, independent_group='message-scenario', scope_id='message'))
    # Callback/Telegram fraud often contains no credential form or web page.
    telegram = [u for u in nav if u.host in {"t.me", "telegram.me"}]
    if THREAT.search(text) and telegram:
        report.reason_codes.append(Evidence("SECURITY_THREAT_TO_MESSENGER",Severity.HIGH,"Угроза финансовой безопасности переводит общение в неподтверждённый мессенджер",{"destinations":[u.original for u in telegram[:3]],"blocking":False},independent_group="message-scenario",scope_id="message"))
    if re.search(r"(?is)(?:удвоени|увелич.{0,20}вдвое).{0,40}баланс|баланс.{0,40}(?:удвоени|вдвое)",text) and re.search(r"(?i)(?:ответ.{0,30}письм|в\s+ответ\s+слово|нажмите.{0,20}ответить)",text):
        report.reason_codes.append(Evidence("REPLY_FOR_REWARD",Severity.HIGH,"Обещание удвоить баланс используется для вовлечения в переписку",{"blocking":False},independent_group="message-scenario",scope_id="message"))


def evaluate_page_scenarios(report):
    for page in report.pages:
        brands = [b for b,_ in catalog() if b["name"] in page.claimed_brands]
        if page.identity_source == "ocr" and (WIN.search(page.text) or REWARD.search(page.text)) and MONEY.search(page.text):
            destinations = [u for u in report.urls if u.scope_id == page.id and (u.source == "ocr:text" or (u.source or "").startswith("qr:"))]
            if any(not official_host(effective_host(u), b["domains"]) for b in brands for u in destinations):
                report.reason_codes.append(Evidence("VISUAL_REWARD_LURE",Severity.HIGH,"Изображение обещает вознаграждение от имени бренда и ведёт вне его доменов",{"brands":page.claimed_brands,"destinations":[u.original for u in destinations[:3]],"blocking":False},independent_group="visual-scenario",scope_id=page.id))
        if not page.url:
            continue
        if brands and INVEST.search(page.text) and not any(official_host(page.host,b["domains"]) for b in brands):
            report.reason_codes.append(Evidence("UNVERIFIED_INVESTMENT_LURE",Severity.HIGH,"Инвестиционное предложение от имени банка размещено вне его доменов",{"page":page.url,"brands":page.claimed_brands,"blocking":False},independent_group="page-scenario",scope_id=page.id))
        if re.search(r"(?i)/(?:wp-includes|wp-content)/(?:theme-compat|uploads|plugins)/",page.url) and re.search(r"(?i)(?:mailbox|webmail|email|почт|邮箱)",page.identity_text) and any("password" in f.sensitive_types and f.collector_observed for f in page.forms):
            report.reason_codes.append(Evidence("MAILBOX_LOGIN_IN_CMS_ASSET",Severity.HIGH,"Вход в почту размещён в каталоге ресурсов CMS; получатель секрета требует проверки",{"page":page.url,"blocking":False},independent_group="page-scenario",scope_id=page.id))
