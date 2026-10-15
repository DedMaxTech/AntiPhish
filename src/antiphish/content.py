"""Russian social-engineering scenarios. Financial words alone are neutral."""
from __future__ import annotations

import re
import unicodedata
import email.utils

from .models import Evidence, Severity
from .policy import catalog, effective_host, official_host
from .urltools import normalize_url, unwrap_url
from .texttools import normalize_russian

AUTH = re.compile(r"(?is)(?:подтверд|восстанов|разблок|продл|обнов|истека|expire|keep|verify|confirm).{0,70}(?:парол|доступ|аккаунт|уч[её]тн|password|account)|(?:парол|password).{0,70}(?:истека|expire|обнов|keep)")
WIN = re.compile(r"(?is)(?:вы\s+(?:получили|выиграли|победили)|вам.{0,25}(?:выпал|начислен|одобрен)|забирайте.{0,20}бонус|получить\s+(?:свой\s+)?(?:подарок|сюрприз)|готово\s+к\s+выводу|генератор.{0,30}(?:выбрал|определил)|выбран.{0,20}победител|за\s+(?:участие|опрос)|программа.{0,10}поощрения|(?:ваучер|топливо).{0,80}(?:бесплатно|подарок))")
MONEY = re.compile(r"(?i)(?:\d[\d\s.,]{2,}\s*(?:₽|руб)|приз|подар|выигрыш|выплат|бонус|ваучер)")
INVEST = re.compile(r"(?is)(?:инвестиц|пассивн.{0,10}доход|прирост.{0,15}капитал).{0,350}(?:\+?\d+\s*%|\d[\d\s]{3,}\s*(?:руб|₽))|(?:\d+\s*%).{0,40}(?:в\s+день|ежеднев|за\s+сутки)")
THREAT = re.compile(r"(?i)(?:несанкционирован|подозрительн.{0,25}активност|не\s+оформляли\s+доверенност|доверенность.{0,100}(?:снятие|перевод)|аккаунт.{0,40}заблокирован)")
CTA = re.compile(r"(?i)(?:получ|забра|подтверд|войти|вывод|вывест|откр|анкет|опрос|тест|активир|перей|куп|использ|обнов|начать|ответ|зарегистр|заверш|перевод|оплат|password|continue|login|verify|sign|update|preview|review|open|restore|confirm|complete|view)")
REWARD = re.compile(r"(?i)(?:подар|выигр|бонус|вознаграж|ваучер|выплат|гарантирован.{0,30}поддержк)")
FINANCE = re.compile(r"(?i)(?:инвестиц|пассивн.{0,10}доход|прирост.{0,15}капитал|доход\s+от|начинайте.{0,15}зарабат)")
ACCOUNT_UPDATE = re.compile(r"(?is)(?:обнов|актуализ|подтверд|восстанов).{0,100}(?:данны|доступ|личн.{0,15}кабинет|уч[её]тн|аккаунт)")
PAYMENT_UPDATE = re.compile(r'(?is)(?:update|verify|confirm|renew).{0,50}(?:payment\s+(?:information|method|details)|billing\s+(?:information|details)|credit\s+card)|(?:плат[её]жн.{0,15}(?:данны|метод)|банковск.{0,15}карт).{0,50}(?:обнов|подтверд)')
ACCOUNT_THREAT = re.compile(r'(?is)(?:mailbox|email|e-mail|account|почт|аккаунт|уч[её]тн).{0,60}(?:restrict|blocked|error|unusual|suspicious|заблок|ошибк|подозрител)|(?:unusual|suspicious|restrict|blocked).{0,60}(?:login|account|mailbox|email)')
ACCOUNT_ACTION = re.compile(r'(?i)(?:login now|log in|validate your identity|verify|this wasn.t me|восстановить доступ|подтвердить личность)')
USER_HOSTING = re.compile(r'(?i)(?:^|\.)(?:ipfs\.io|cloudflare-ipfs\.com|on-fleek\.app|pages\.dev|workers\.dev|github\.io|blogspot\.com)$')
TRANSFER_COMPLETION = re.compile(r'(?is)(?:заверш(?:ите|ить)|подтверд(?:ите|ить)|получ(?:ите|ить)).{0,60}(?:вывод\s+средств|перевод|выплат)|(?:withdrawal|transfer).{0,60}(?:pending|complete|confirm)')
TRANSFER_DETAILS = re.compile(r'(?i)(?:реквизит|данны.{0,15}карт|bank\s+details|account\s+number)')


def evaluate_message(extracted, report):
    if extracted.kind != "eml":
        return
    # NFC + removal of zero width/combining noise makes Russian lures robust
    # without treating IDNs or Cyrillic themselves as malicious.
    text = normalize_russian(extracted.metadata.get("subject", "") + " " + extracted.metadata.get("message_text", extracted.text))
    declaration = normalize_russian(extracted.metadata.get("subject","") + " " + " ".join(p.identity_text for p in extracted.pages if p.id in extracted.metadata.get("message_scopes",set())))
    brands = [b for b, patterns in catalog() if any(p.search(declaration.casefold()) for p in patterns)]
    sender = extracted.metadata.get("from_domain")
    display_sender = email.utils.parseaddr(extracted.metadata.get("headers",{}).get("from",""))[0]
    if display_sender:
        brands = [b for b, patterns in catalog() if any(p.search((declaration+" "+normalize_russian(display_sender)).casefold()) for p in patterns)]
    scopes = extracted.metadata.get("message_scopes",set())
    nav = [u for u in report.urls if (u.scope_id is None or u.scope_id in scopes) and (u.source in {"html:a:href", "link-wrapper", "javascript-navigation", "text", "ocr:text"} or (u.source or "").startswith("qr:")) and "ACTION_URL" not in u.flags]
    candidates = [u for u in nav if not u.displayed_text or CTA.search(normalize_russian(u.displayed_text)) or ACCOUNT_ACTION.search(normalize_russian(u.displayed_text))]
    details = {"brands":[b["name"] for b in brands], "from_domain":sender}
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
        if (WIN.search(text) or (REWARD.search(text) and re.search(r"(?i)(?:опрос|получ|забрат|активир|гарантирован)",text))) and MONEY.search(text):
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
            report.reason_codes.append(Evidence(code, Severity.HIGH, "Действие от имени бренда ведёт вне его доменов, а отправитель не подтверждён", {**details,"brand":brand["name"],"destinations":[u.original for u in external[:3]], "blocking":False}, independent_group="message-scenario", scope_id="message"))
        elif brand['name'] in {'DocuSign', 'Adobe', 'Dropbox'} and re.search(r'(?i)(?:view|preview|review|sign|просмотр|подпис).{0,40}(?:document|pdf|документ)', text) and any(USER_HOSTING.search(effective_host(u) or '') for u in external):
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
