"""Brand-independent attack behaviours. Each alert retains its exact trigger."""
import re
from urllib.parse import urlsplit

from .models import Evidence,Severity
from .texttools import normalize_russian

REVIEW_CODES={'SECRET_REPLY_REQUEST','CLICKFIX_EXECUTION','UPFRONT_PAYOUT_FEE','SAFE_ACCOUNT_TRANSFER','REMOTE_BANK_CONTROL','SECRET_TO_PUBLIC_FORM','FAKE_BROWSER_ADDRESS'}
EDUCATIONAL=re.compile(r'(?i)(?:памятка|как\s+(?:распознать|защититься)|защита\s+от|пример\s+(?:фишинга|мошенничества)|security awareness|phishing awareness|how to (?:spot|avoid))')
SECRET=re.compile(r'(?i)(?:парол\w*|password|(?:код\w*[^.!?\n]{0,30}(?:смс|sms|подтвержден|входа))|(?:cvv|cvc)|seed\s+phrase|сид.?фраз\w*|секретн\w*\s+ключ\w*)')
REPLY=re.compile(r'(?i)(?<!\w)(?:отправьте|пришлите|сообщите|перешлите|назовите|продиктуйте|send|reply\s+with|provide\s+us\s+with)\b[^.!?\n]{0,110}')
SAFE_TRANSFER=re.compile(r'(?i)(?<!\w)(?:переведите|перечислите|transfer|move)[^.!?\n]{0,120}(?:безопасн\w*\s+сч[её]т|защищ[её]нн\w*\s+сч[её]т|safe\s+account)')
PAYOUT_FEE=re.compile(r'(?is)(?:оплатите|внесите|переведите|pay|deposit)[^.!?\n]{0,65}(?:комисси\w*|страхов\w*\s+взнос|налог|verification\s+fee|release\s+fee)[^.!?\n]{0,150}(?:вывод\w*\s+(?:денег|средств)|получ\w*\s+(?:денежн\w*\s+)?(?:выигрыш|выплат|компенсац)|release.{0,15}(?:funds|winnings))|(?:для\s+(?:получения|вывода)[^.!?\n]{0,35}(?:выигрыш|выплат|компенсац|средств|денег))[^.!?\n]{0,100}(?:оплатите|внесите|переведите)[^.!?\n]{0,45}(?:комисси\w*|налог|взнос)')


def quoted_or_negated(text,start):
    before=text[max(0,start-140):start]
    return bool(re.search(r"(?i)(?:\bне\s+|никогда\s+(?:не\s+)?|do\s+not\s+|don't\s+|never\s+|нельзя\s+)$",before)
        or re.search(r'(?i)(?:мошенники\s+(?:просят|пишут)|пример\s+атаки|цитата\s+из\s+фишинга|scammers\s+(?:ask|say))[^.!?\n]{0,70}$',before))


def add(report,code,summary,text,start,end,scope,**extra):
    trigger=text[start:end][:350]
    report.reason_codes.append(Evidence(code,Severity.HIGH,summary,
        {'matched_text':trigger,'trigger_matches':[{'text':trigger,'role':'attack-behaviour'}],
         'explanation':summary,'blocking':False,**extra},independent_group='attack-behaviour',scope_id=scope))


def inspect_text(report,text,scope,*,heading='',markup='',forms=False):
    text=normalize_russian(text)
    # A security lesson with no active secret collector is not an instruction.
    if not forms and EDUCATIONAL.search(heading+' '+text[:250]):return
    for match in REPLY.finditer(text):
        secret=SECRET.search(match.group())
        reset_artifact=secret and re.match(r'(?i)\s*(?:reset\s+(?:link|email|instructions)|recovery\s+(?:link|instructions)|(?:для\s+)?(?:сброса|восстановления))',match.group()[secret.end():])
        if secret and not reset_artifact and not quoted_or_negated(text,match.start()):
            add(report,'SECRET_REPLY_REQUEST','Просят сообщить пароль, код или другой секрет собеседнику',text,match.start(),match.start()+secret.end(),scope);break
    for pattern,code,title in [(SAFE_TRANSFER,'SAFE_ACCOUNT_TRANSFER','Просят перевести деньги на «безопасный счёт»'),
                              (PAYOUT_FEE,'UPFRONT_PAYOUT_FEE','Требуют комиссию перед получением денежной выплаты')]:
        for m in pattern.finditer(text):
            if not quoted_or_negated(text,m.start()):add(report,code,title,text,m.start(),m.end(),scope);break
    gate=re.search(r'(?i)(?:captcha|капч|провер\w*[^.!?]{0,30}(?:человек|браузер)|verify[^.!?]{0,30}human|ошибк\w*[^.!?]{0,30}(?:браузер|документ)|подтвердите[^.!?]{0,25}не робот)',text)
    paste=re.search(r'(?i)(?:win(?:dows)?\s*\+\s*r|win(?:dows)?\s*\+\s*x|вставьте.{0,40}(?:команд|код)|paste.{0,40}(?:command|code))',text)
    code=re.search(r'(?is)(?:powershell|pwsh|mshta|cmd(?:\.exe)?)[^\n<>]{0,240}(?:https?://|-(?:enc|encodedcommand)\b|\biex\b)|(?:curl|wget)[^\n<>]{0,180}\|\s*(?:bash|sh)',markup or text)
    if gate and paste and code and not quoted_or_negated(text,paste.start()):
        add(report,'CLICKFIX_EXECUTION','Под видом проверки предлагают вставить и запустить системную команду',text,min(gate.start(),paste.start()),max(gate.end(),paste.end()),scope,matched_code=code.group()[:500])
    remote=re.search(r'(?i)(?:установите|скачайте|install|download)[^.!?\n]{0,70}(?:anydesk|rustdesk|teamviewer|screenconnect)',text)
    banking=re.search(r'(?i)(?:банковск\w*\s+приложени|защит\w*\s+(?:средств|денег|сч[её]та)|спасти\s+(?:деньги|средства))',text)
    access=re.search(r'(?i)(?:передайте|сообщите|продиктуйте)[^.!?\n]{0,45}(?:код\s+подключения|id\s+(?:подключения|устройства))',text)
    if remote and banking and access and not quoted_or_negated(text,remote.start()):
        add(report,'REMOTE_BANK_CONTROL','Для защиты банковских средств требуют программу удалённого доступа и код подключения',text,remote.start(),remote.end(),scope)


def evaluate(extracted,report):
    report.reason_codes[:]=[e for e in report.reason_codes if e.code not in REVIEW_CODES]
    if extracted.kind=='eml':inspect_text(report,extracted.metadata.get('message_text',extracted.text),'message',heading=extracted.metadata.get('subject',''),markup=extracted.html_text)
    for page in report.pages:
        if page.id not in extracted.metadata.get('message_scopes',set()):
            inspect_text(report,page.text,page.id,heading=page.title,markup=page.source_html,forms=bool(page.forms))
        address_bars=[]
        if page.source_html and any(f.collector_observed and set(f.sensitive_types)&{'password','otp','wallet_secret'} for f in page.forms):
            from lxml import html
            from .urltools import extract_urls
            try:
                tree=html.fromstring(page.source_html)
                for bar in tree.xpath('//*[@class or @id]')[:500]:
                    if re.search(r'(?i)address[-_]?bar|url[-_]?bar|browser[-_]?(?:url|address)',bar.get('class','')+' '+bar.get('id','')):
                        address_bars.extend(extract_urls(bar.get('value','')+' '+bar.text_content()))
            except (ValueError,TypeError):pass
        for form in page.forms:
            if not form.collector_observed or not set(form.sensitive_types)&{'password','otp','wallet_secret'}:continue
            p=urlsplit(form.destination or '');host=p.hostname or ''
            generic=(host in {'formsubmit.co','api.web3forms.com','formspree.io','getform.io'}
                or host=='docs.google.com' and p.path.startswith('/forms/') and 'formResponse' in p.path)
            if generic:
                report.reason_codes.append(Evidence('SECRET_TO_PUBLIC_FORM',Severity.HIGH,
                    'Секрет передаётся в сервис обычных анкет или обратной связи',
                    {'form_id':form.id,'destination':form.destination,'sensitive_types':form.sensitive_types,'blocking':False},independent_group='attack-behaviour',scope_id=page.id))
            from .urltools import normalize_url,same_site
            for raw in address_bars:
                try:shown=normalize_url(raw)
                except ValueError:continue
                if not same_site(shown.host,page.host) and not same_site(shown.host,form.destination_host):
                    report.reason_codes.append(Evidence('FAKE_BROWSER_ADDRESS',Severity.HIGH,'Форма входа рисует адрес другого сайта внутри страницы',
                        {'form_id':form.id,'displayed_origin':shown.redacted,'destination':form.destination,'matched_text':raw,'blocking':False},independent_group='attack-behaviour',scope_id=page.id))
                    break
