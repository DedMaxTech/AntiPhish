import io
import json
import base64

from PIL import Image

from antiphish.analyzer import Analyzer
from antiphish.config import RESOURCE_DIR
from antiphish.models import Verdict
from antiphish.options import resolve
from antiphish.textmodel import text_windows


class Tokenizer:
    def num_special_tokens_to_add(self,pair=False):return 2
    def __call__(self,text,**kwargs):return {'input_ids':list(range(len(text.split())))}


def test_window_coverage_keeps_tail_and_bounds_work():
    windows,spans,total,limited=text_windows('word '*2500,Tokenizer())
    assert len(windows)==6 and spans[0][0]==0 and spans[-1][1]==total
    assert all(len(w)<=382 for w in windows) and limited
    assert text_windows('short text',Tokenizer())[2:]==(2,False)
    assert len(text_windows('word '*900,Tokenizer(),max_windows=1)[0])==1
    # A huge whitespace prefix must not silently hide a short tail after the
    # character cap, nor claim that every input character was inspected.
    windows,_,_,limited=text_windows(' '*60000+'secret at the end',Tokenizer())
    assert windows[0] and limited


def test_default_profiles_retire_siglip_but_keep_explicit_experiment():
    assert not resolve('deep')['siglip'] and not resolve('deep')['logo_references']
    assert resolve('quality')['visual_brands'] and not resolve('fast')['visual_brands']
    assert resolve('custom',{'siglip':True})['siglip']


def test_accessible_logo_identity_and_official_control(empty_kb):
    body=b'<header><a href="/"><img class="logo" alt="Wildberries"></a></header><form method=post action="/auth"><input type=password name=password></form>'
    analyzer=Analyzer(empty_kb)
    assert analyzer.analyze(body,name='login.html',base_url='https://collector.example/').verdict==Verdict.PHISHING
    assert analyzer.analyze(body,name='login.html',base_url='https://wildberries.ru/').verdict==Verdict.NOT_DETECTED


def test_oauth_button_and_article_image_are_not_account_identity(empty_kb):
    for image in ['<button>Continue with <img class="logo" alt="Google"></button>',
                  '<article><img alt="Google"></article>']:
        body=('<h1>My account</h1><form method=post>'+image+'<input type=password name=pass></form>').encode()
        assert Analyzer(empty_kb).analyze(body,name='login.html',base_url='https://mycompany.example/').verdict==Verdict.NOT_DETECTED


def test_partner_brand_does_not_override_real_auth_origin(empty_kb):
    body='<h1>Т-Банк: вход и доступ к Госуслугам</h1><form method=post action="https://tbank.ru/auth"><input type=password></form>'.encode()
    report=Analyzer(empty_kb).analyze(body,name='login.html',base_url='https://tbank.ru/')
    assert report.verdict==Verdict.NOT_DETECTED
    assert 'PHISHING_FORM_ROUTE' not in {e.code for e in report.reason_codes}
    bad=Analyzer(empty_kb).analyze(body.replace(b'https://tbank.ru/auth',b'https://collector.example/auth'),name='login.html',base_url='https://collector.example/')
    assert bad.verdict==Verdict.PHISHING


def test_logo_localization_abstains_on_unknown_and_preserves_region():
    from antiphish.visual import match_image
    rows=[json.loads(l) for l in (RESOURCE_DIR/'logo-gallery/manifest.jsonl').read_text(encoding='utf-8').splitlines() if l.strip()]
    row=next(r for r in rows if r['brand']=='Wildberries')
    logo=Image.open(RESOURCE_DIR/'logo-gallery'/row['path']).convert('RGBA').resize((110,110))
    image=Image.new('RGB',(800,600),'white');image.paste(logo,(45,35),logo)
    stream=io.BytesIO();image.save(stream,'PNG')
    result=match_image(stream.getvalue())
    match=next(r for r in result['brand_candidates'] if r['brand']=='Wildberries')
    assert abs(match['roi'][0]-45)<8 and abs(match['roi'][1]-35)<8
    assert result['accepted_identity'] is None and not result['blocking']
    stream=io.BytesIO();Image.new('RGB',(800,600),'white').save(stream,'PNG')
    assert match_image(stream.getvalue())['brand_candidates']==[]


def test_visual_logo_alone_never_blocks_a_page(empty_kb,monkeypatch):
    from antiphish.network import FetchResult
    buffer=io.BytesIO();Image.new('RGB',(800,600),'white').save(buffer,'PNG')
    def fetch(url,limits):
        return FetchResult(b'<h1>Account</h1><form action="/auth" method=post><input type=password></form>',url,[url],'text/html','200',screenshot=buffer.getvalue())
    monkeypatch.setattr('antiphish.visual.match_image',lambda blob:{'model':'Local-logo-geometry','status':'COMPLETE','image_size':[800,600],'brand_candidates':[{'brand':'Wildberries','roi':[10,10,120,120],'method':'sift-ransac','inliers':14}],'blocking':False})
    r=Analyzer(empty_kb).analyze('https://collector.example/',network='http',fetcher=fetch,profile='custom',options={'ocr':False,'qr':False})
    assert r.verdict==Verdict.SUSPICIOUS
    assert 'VISUAL_BRAND_AUTH_MISMATCH' in {e.code for e in r.reason_codes}
    clean=Analyzer(empty_kb).analyze('https://wildberries.ru/',network='http',fetcher=fetch,profile='custom',options={'ocr':False,'qr':False})
    assert clean.verdict==Verdict.NOT_DETECTED


def test_http_logo_asset_is_not_a_navigation_and_offline_never_fetches(empty_kb):
    from antiphish.network import FetchResult
    rows=[json.loads(l) for l in (RESOURCE_DIR/'logo-gallery/manifest.jsonl').read_text(encoding='utf-8').splitlines() if l.strip()]
    row=next(r for r in rows if r['brand']=='Wildberries')
    image=(RESOURCE_DIR/'logo-gallery'/row['path']).read_bytes()
    body=b'<img class="logo" src="https://cdn.example/brand.png"><form method=post action="/auth"><input type=password></form>'
    calls=[]
    def fetch(url,limits):
        calls.append(url)
        return FetchResult(image if 'cdn.' in url else body,url,[url],'image/png' if 'cdn.' in url else 'text/html','200')
    a=Analyzer(empty_kb)
    report=a.analyze('https://collector.example/',network='http',fetcher=fetch,options={'ocr':False,'qr':False})
    assert calls==['https://collector.example/','https://cdn.example/brand.png']
    assert report.verdict==Verdict.SUSPICIOUS and report.configuration['network_pages_fetched']==1
    assert report.pages[0].image_role=='logo-asset'
    assert report.configuration['decision']['reasons'][0]['code']=='VISUAL_BRAND_AUTH_MISMATCH'
    clean=a.analyze('https://wildberries.ru/',network='http',fetcher=fetch,options={'ocr':False,'qr':False})
    assert clean.verdict==Verdict.NOT_DETECTED
    calls.clear()
    offline=a.analyze(body,name='source.html',base_url='https://collector.example/',network='offline',fetcher=fetch,options={'ocr':False,'qr':False})
    assert calls==[] and offline.verdict==Verdict.NOT_DETECTED


def test_embedded_logo_is_bound_to_its_form_page(empty_kb):
    rows=[json.loads(l) for l in (RESOURCE_DIR/'logo-gallery/manifest.jsonl').read_text(encoding='utf-8').splitlines() if l.strip()]
    row=next(r for r in rows if r['brand']=='Wildberries')
    encoded=base64.b64encode((RESOURCE_DIR/'logo-gallery'/row['path']).read_bytes()).decode()
    body=('<img class="logo" src="data:image/png;base64,'+encoded+'"><form method=post action="/auth"><input type=password></form>').encode()
    report=Analyzer(empty_kb).analyze(body,name='login.html',base_url='https://collector.example/',options={'ocr':False,'qr':False})
    assert report.verdict==Verdict.SUSPICIOUS
    page=next(p for p in report.pages if p.forms)
    assert page.image_role=='embedded-logo'
    assert next(e for e in report.reason_codes if e.code=='VISUAL_BRAND_AUTH_MISMATCH').scope_id==page.id


def test_svg_accessible_name_is_an_identity_declaration(empty_kb):
    body=b'<header><svg class="logo"><title>Wildberries</title></svg></header><form action="/auth" method=post><input type=password></form>'
    report=Analyzer(empty_kb).analyze(body,name='login.html',base_url='https://collector.example/')
    assert report.verdict==Verdict.PHISHING
    assert all(e.context['policy_role']=='observation' for e in report.reason_codes if e.code=='SENSITIVE_FORM')


def test_homograph_needs_secret_form_and_cyrillic_is_not_a_signal(empty_kb):
    from antiphish.domainidentity import lookalikes
    import idna
    bad=idna.encode('аррӏе.com').decode()
    assert any(m[0]=='Apple' for m in lookalikes(bad))
    a=Analyzer(empty_kb)
    body=b'<h1>Account access</h1><form method=post action="/auth"><input type=password></form>'
    report=a.analyze(body,name='login.html',base_url='https://'+bad+'/')
    assert report.verdict==Verdict.SUSPICIOUS
    assert 'LOOKALIKE_SECRET_FORM' in {e.code for e in report.reason_codes}
    safe=a.analyze(b'<h1>News</h1><p>Discussion of a domain</p>',name='article.html',base_url='https://'+bad+'/')
    assert safe.verdict==Verdict.NOT_DETECTED
    russian=a.analyze(body,name='login.html',base_url='https://пример.рф/')
    assert russian.verdict==Verdict.NOT_DETECTED


def test_extra_ca_never_disables_verification(monkeypatch,tmp_path):
    import ssl
    import pytest
    from antiphish.network import tls_context
    monkeypatch.delenv('ANTIPHISH_CA_BUNDLE',raising=False)
    context=tls_context()
    assert context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED
    monkeypatch.setenv('ANTIPHISH_CA_BUNDLE',str(tmp_path/'missing.pem'))
    with pytest.raises(ValueError):tls_context()
    file=tmp_path/'invalid.pem';file.write_text('This is not a CA certificate')
    monkeypatch.setenv('ANTIPHISH_CA_BUNDLE',str(file))
    with pytest.raises(ssl.SSLError):tls_context()


def test_model_hypothesis_cannot_overturn_verified_login(empty_kb,monkeypatch):
    result={'model':'Qwen-test','suspicious':True,'parse_status':'OK','structured_extract':{
        'credential_request':True,'payment_change':False,'impersonation':True,'evidence_spans':['Т-Банк','password']}}
    monkeypatch.setattr('antiphish.analyzer.optional_deep_analysis',lambda *a,**k:([result],[]))
    body='<h1>Т-Банк</h1><form action="/auth" method=post><input type=password></form>'.encode()
    r=Analyzer(empty_kb).analyze(body,name='login.html',base_url='https://tbank.ru/',profile='custom',options={'llm':True,'visual_brands':False})
    assert r.verdict==Verdict.NOT_DETECTED
    assert any(e.code=='MODEL_SUSPICION' and e.context['policy_role']=='observation' for e in r.reason_codes)


def test_direct_secret_request_after_long_preamble_needs_brand_and_foreign_url(empty_kb):
    from email.message import EmailMessage
    def message(tail):
        mail=EmailMessage();mail['Subject']='Обновление';mail.set_content('Итоги рабочего совещания. '*300+tail)
        return mail.as_bytes()
    a=Analyzer(empty_kb)
    tail='Ваш Сбербанк заблокирован. Срочно введите пароль и код из СМС на https://bank-help.example/verify для разблокировки.'
    r=a.analyze(message(tail),name='message.eml',profile='fast')
    assert r.verdict==Verdict.SUSPICIOUS
    evidence=next(e for e in r.reason_codes if e.code=='BRANDED_SECRET_INSTRUCTION')
    assert 'введите пароль' in evidence.context['text_excerpt'].lower()
    official=tail.replace('https://bank-help.example/verify','https://online.sberbank.ru/login')
    assert a.analyze(message(official),name='message.eml',profile='fast').verdict==Verdict.NOT_DETECTED
    warning='Сбербанк предупреждает: мошенники пишут «введите пароль на https://bank-help.example/verify». Не передавайте пароли.'
    assert a.analyze(message(warning),name='message.eml',profile='fast').verdict==Verdict.NOT_DETECTED
    payment='Оплата заказа картой Visa. Введите CVV на https://checkout.example/verify для подтверждения оплаты.'
    assert a.analyze(message(payment),name='message.eml',profile='fast').verdict==Verdict.NOT_DETECTED
    contact='Контакт администратора support@mail.ru. Введите пароль на https://intranet.example/login для доступа к порталу.'
    assert a.analyze(message(contact),name='message.eml',profile='fast').verdict==Verdict.NOT_DETECTED
