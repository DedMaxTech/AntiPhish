import json
from email.message import EmailMessage
from pathlib import Path

from antiphish.analyzer import Analyzer
from antiphish.models import Verdict,PageFinding,FormFinding,AnalysisReport


def prediction(text,phish=.995,fraud=.997):
    return [{'model':'Laya multilingual','status':'COMPLETE','scores':{'phishing':phish},
             'fraud_score':fraud,'evidence_text':text,'suspicious':False}],[]


def test_deep_enables_both_text_models():
    from antiphish.options import resolve
    deep=resolve('deep')
    assert deep['text_model'] and deep['laya'] and deep['llm']
    assert not resolve('quality')['laya']


def test_dom_template_preserves_parent_child_structure():
    from antiphish.extractors import extract_html
    from antiphish.config import DEFAULT_LIMITS
    a=extract_html(b'<div><form><input type=password><p>Account access</p></form></div>',DEFAULT_LIMITS).pages[0]
    b=extract_html(b'<form><div><p>Account access</p><input type=password></div></form>',DEFAULT_LIMITS).pages[0]
    assert a.legacy_dom_signature==b.legacy_dom_signature
    assert a.dom_signature.startswith('v2:') and b.dom_signature.startswith('v2:')
    assert (int(a.dom_signature[3:],16)^int(b.dom_signature[3:],16)).bit_count()>3


def test_template_ignores_random_attribute_values():
    from antiphish.extractors import extract_html
    from antiphish.config import DEFAULT_LIMITS
    a=extract_html(b'<form id="random1" action="/auth"><input name=p type=password></form>',DEFAULT_LIMITS).pages[0]
    b=extract_html(b'<form id="random2" action="/other"><input name=p type=password></form>',DEFAULT_LIMITS).pages[0]
    assert a.dom_signature==b.dom_signature


def test_static_render_keeps_vectors_but_removes_active_content():
    from antiphish.localrender import safe_markup
    source='<script>alert(1)</script><iframe src="http://localhost/x"></iframe><svg><path d="M0 0L10 10"/></svg><img src="cid:logo"><form action="https://bad.example"><input value="secret" onfocus="alert(2)"></form>'
    safe=safe_markup(source,{'cid:logo':'data:image/png;base64,AAAA'})
    assert '<script' not in safe and '<iframe' not in safe and 'onfocus' not in safe and 'value="secret"' not in safe
    assert '<svg' in safe and 'data:image/png' in safe and "script-src 'none'" in safe


def test_mail_cid_svg_is_rendered_and_its_brand_is_used(empty_kb):
    mail=EmailMessage();mail['Subject']='Уведомление';mail.set_content('Вы выиграли подарок 5000 рублей. Получите подарок по ссылке.')
    mail.add_alternative('<html><body><img src="cid:logo"><p>Вы выиграли подарок 5000 рублей!</p><a href="https://reward.example/gift">Получить подарок</a></body></html>',subtype='html')
    mail.get_payload()[-1].add_related(b'<svg xmlns="http://www.w3.org/2000/svg" width="550" height="130"><rect width="550" height="130" fill="white"/><text x="15" y="90" font-family="Arial" font-size="65" fill="purple">Wildberries</text></svg>',maintype='image',subtype='svg+xml',cid='<logo>',filename='logo.svg')
    report=Analyzer(empty_kb).analyze(mail.as_bytes(),name='mail.eml')
    assert report.analysis_status.value!='FAILED',report.warnings
    assert report.configuration['local_render']['rendered']>=1
    assert report.configuration['local_render']['network'] is False
    candidates=[(m,c) for m in report.model_evidence for c in m.get('brand_candidates',[]) if c['brand']=='Wildberries']
    assert candidates
    reason=next(e for e in report.reason_codes if e.code=='UNVERIFIED_REWARD_LURE')
    assert reason.details['brand']=='Wildberries'
    assert reason.details['identity_comparison']['basis']=='visual-and-action-link'
    assert report.verdict==Verdict.SUSPICIOUS


def test_pdf_with_native_text_also_has_a_full_render(empty_kb):
    import fitz
    doc=fitz.open();page=doc.new_page(width=600,height=800)
    page.insert_text((40,70),'Wildberries',fontsize=38)
    page.insert_text((40,150),'Native PDF text: this is long enough to bypass the scanned-page condition.',fontsize=12)
    page.draw_rect(fitz.Rect(40,200,400,280),color=(.5,0,.8),fill=(.5,0,.8))
    report=Analyzer(empty_kb).analyze(doc.tobytes(),name='vector.pdf',options={'ocr':False,'qr':False})
    doc.close()
    assert any(p.image_role=='pdf-render' and p.image_bytes for p in report.pages)
    assert report.verdict==Verdict.NOT_DETECTED


def test_identical_logo_keeps_both_page_owners(monkeypatch):
    from antiphish.visualpipeline import inspect
    calls=[]
    def match(blob):
        calls.append(blob)
        return {'model':'Local-logo-geometry','image_size':[100,100],'brand_candidates':[]}
    monkeypatch.setattr('antiphish.visual.match_image',match)
    pages=[PageFinding('page:'+str(i),'hash',image_bytes=b'same-logo') for i in range(2)]
    evidence,warnings=inspect(pages,ocr=False)
    assert len(calls)==1 and not warnings
    assert {x['image_context']['scope_id'] for x in evidence}=={'page:0','page:1'}


def test_model_can_request_review_without_claiming_proof(empty_kb,monkeypatch):
    text='Ваш доступ остановлен. Введите пароль на https://portal-help.example/login.'
    monkeypatch.setattr('antiphish.layamodel.configured_score',lambda t:prediction(text))
    mail=EmailMessage();mail.set_content(text)
    report=Analyzer(empty_kb).analyze(mail.as_bytes(),name='mail.eml',profile='fast',options={'laya':True})
    assert report.verdict==Verdict.SUSPICIOUS
    assert report.configuration['decision']['ai_based'] is True
    reason=next(e for e in report.reason_codes if e.code=='AI_MODEL_REVIEW')
    assert reason.context['selection']=='model-input' and 'Введите пароль' in reason.context['text_excerpt']
    assert report.model_evidence[0]['affects_verdict'] is True


def test_wrong_model_score_does_not_flag_security_advice(empty_kb,monkeypatch):
    text='Никогда не сообщайте пароль. Памятка https://help.example/security.'
    monkeypatch.setattr('antiphish.layamodel.configured_score',lambda t:prediction(text))
    mail=EmailMessage();mail.set_content(text)
    report=Analyzer(empty_kb).analyze(mail.as_bytes(),name='mail.eml',profile='fast',options={'laya':True})
    assert report.verdict==Verdict.NOT_DETECTED


def test_agreement_counts_independent_encoders(empty_kb,monkeypatch):
    monkeypatch.setattr('antiphish.layamodel.configured_score',lambda t:prediction('Подозрительная переписка',.94,.93))
    monkeypatch.setattr('antiphish.textmodel.configured_score',lambda *a,**k:([{'model':'Horizon-Labs/phishing-scam-detector-base','scores':{'fraud':.95},'evidence_text':'Подозрительная переписка','suspicious':False}],[]))
    mail=EmailMessage();mail.set_content('Подозрительная переписка')
    report=Analyzer(empty_kb).analyze(mail.as_bytes(),name='mail.eml',profile='fast',options={'laya':True,'text_model':True})
    assert report.verdict==Verdict.SUSPICIOUS and report.configuration['decision']['ai_based']
    assert report.configuration['model_consensus']['independent_families']==2


def test_model_warning_does_not_overturn_verified_bank_login(empty_kb,monkeypatch):
    monkeypatch.setattr('antiphish.layamodel.configured_score',lambda t:prediction('Введите пароль на https://tbank.ru/login'))
    body='<h1>Т-Банк</h1><p>Введите пароль</p><form action="/auth" method=post><input type=password></form>'
    report=Analyzer(empty_kb).analyze(body.encode(),name='login.html',base_url='https://tbank.ru/',profile='fast',options={'laya':True})
    assert report.verdict==Verdict.NOT_DETECTED


def test_multiple_views_produce_one_brand_form_reason():
    from antiphish.policy import evaluate_pages
    page=PageFinding('page:test','hash',host='foreign.example')
    page.forms=[FormFinding('form:test',page.id,['password'],['password'],'post','https://foreign.example/send','foreign.example',True)]
    report=AnalysisReport(pages=[page])
    for i in range(2):report.model_evidence.append({'model':'Local-logo-geometry','image_size':[1000,1000],
        'image_context':{'scope_id':page.id,'artifact_id':str(i)},'brand_candidates':[{'brand':'Wildberries','method':'sift-ransac','roi':[10,10,200,70]}]})
    evaluate_pages(report)
    reasons=[e for e in report.reason_codes if e.code=='VISUAL_BRAND_AUTH_MISMATCH']
    assert len(reasons)==1 and len(reasons[0].details['visual_views'])==2


def test_http_svg_logo_is_rendered_without_extra_network(empty_kb):
    from antiphish.network import FetchResult
    calls=[]
    svg=b'<svg xmlns="http://www.w3.org/2000/svg" width="550" height="130"><text x="15" y="90" font-family="Arial" font-size="65" fill="purple">Wildberries</text></svg>'
    body=b'<img class=logo src="/logo.svg"><h1>Login</h1><form action="/auth" method=post><input type=password></form>'
    def fetch(url,limits):
        calls.append(url)
        return FetchResult(svg if url.endswith('.svg') else body,url,[url],'image/svg+xml' if url.endswith('.svg') else 'text/html','200')
    report=Analyzer(empty_kb).analyze('https://foreign.example/',network='http',fetcher=fetch)
    assert calls==['https://foreign.example/','https://foreign.example/logo.svg']
    assert report.verdict==Verdict.SUSPICIOUS
    assert report.configuration['visual_assets']['observations'][0]['status']=='FETCHED_VECTOR'
