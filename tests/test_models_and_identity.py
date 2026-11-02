import json
from PIL import Image

from antiphish.analyzer import Analyzer
from antiphish.models import Verdict
from antiphish.brandvision import wordmarks


def test_laya_option_is_separate_from_final_verdict(empty_kb,monkeypatch):
    calls=[]
    def predict(text):
        calls.append(text)
        return [{'model':'Laya multilingual','assessment':'phishing','scores':{'phishing':.999},'suspicious':False,'affects_verdict':False}],[]
    monkeypatch.setattr('antiphish.layamodel.configured_score',predict)
    analyzer=Analyzer(empty_kb)
    assert analyzer.analyze(b'Routine meeting',name='note.txt').verdict==Verdict.NOT_DETECTED
    assert not calls
    report=analyzer.analyze(b'Routine meeting',name='note.txt',options={'laya':True})
    assert len(calls)==1 and report.verdict==Verdict.NOT_DETECTED
    assert report.model_evidence[0]['assessment']=='phishing'
    assert 'local-laya-decisions' in report.configuration['stages']
    assert report.configuration['decision']['reasons']==[]


def test_missing_laya_is_explicit_without_downloads(monkeypatch):
    from antiphish import layamodel
    monkeypatch.setattr(layamodel,'status',lambda:{'ready':False})
    monkeypatch.setattr(layamodel,'_load',lambda *a:(_ for _ in ()).throw(AssertionError('Should not load')))
    evidence,warnings=layamodel.configured_score('Some text')
    assert evidence[0]['status']=='UNAVAILABLE' and warnings
    assert layamodel.configured_score(' ')[0][0]['status']=='NO_TEXT'


def test_header_wordmarks_are_localized_not_article_mentions():
    def line(text,y,score=.99):return {'text':text,'score':score,'roi':[10,y,250,y+40]}
    assert wordmarks([line('Wildberries',20)],(1000,1000))[0]['brand']=='Wildberries'
    assert not wordmarks([line('Wildberries',750)],(1000,1000))
    assert not wordmarks([line('Wildberries',20,.7)],(1000,1000))
    assert not wordmarks([line('Новости компании Wildberries сегодня',20)],(1000,1000))
    assert not wordmarks([line('Visa',20)],(1000,1000))
    assert wordmarks([line('Wildberries',750)],(1000,1000),logo_asset=True)


def test_news_article_with_own_login_is_not_bank_impersonation(empty_kb):
    body='<title>Сбербанк открыл офис</title><article><h1>Сбербанк открыл офис</h1><p>Новость редакции</p></article><form action="/login" method=post><input type=password></form>'
    analyzer=Analyzer(empty_kb)
    report=analyzer.analyze(body.encode(),name='news.html',base_url='https://news.example/')
    assert report.verdict==Verdict.NOT_DETECTED
    fake=body.replace('<article>','<header><img class=logo alt="Сбербанк"></header><article>')
    report=analyzer.analyze(fake.encode(),name='login.html',base_url='https://news.example/')
    assert report.verdict==Verdict.PHISHING
    assert any(c['status']=='foreign_secret_collector' for c in report.configuration['brand_checks'])


def test_user_content_is_not_provider_otp_authentication(empty_kb):
    analyzer=Analyzer(empty_kb)
    for name,base in [('Google','https://docs.google.com/forms/x'),('Яндекс','https://forms.yandex.ru/x')]:
        body=f'<h1>{name}</h1><form method=post><input name=otp autocomplete=one-time-code></form>'
        report=analyzer.analyze(body.encode(),name='form.html',base_url=base)
        assert report.verdict==Verdict.PHISHING
        assert any(c['status']=='foreign_secret_collector' for c in report.configuration['brand_checks'])
    official=analyzer.analyze(b'<h1>Google</h1><form method=post><input name=otp autocomplete=one-time-code></form>',name='login.html',base_url='https://accounts.google.com/')
    assert official.verdict==Verdict.NOT_DETECTED
    assert official.configuration['brand_checks'][0]['status']=='verified'
    survey=analyzer.analyze(b'<h1>Google Forms</h1><form method=post><input name=otp autocomplete=one-time-code></form>',name='survey.html',base_url='https://docs.google.com/forms/x')
    assert survey.verdict==Verdict.NOT_DETECTED
    assert survey.configuration['brand_checks'][0]['status']=='provider_context'


def test_ocr_identity_supports_review_of_real_dom_form(empty_kb,monkeypatch):
    from antiphish.models import AnalysisReport,PageFinding,FormFinding
    from antiphish.policy import evaluate_pages,arbitrate
    report=AnalysisReport()
    page=PageFinding('page:demo','hash',url='https://foreign.example/',host='foreign.example',identity_source='ocr')
    page.forms=[FormFinding('form:demo',page.id,['password'],['password'],'post','https://foreign.example/send','foreign.example',True)]
    report.pages=[page]
    report.model_evidence=[{'model':'Local-logo-geometry','image_size':[1000,1000],
        'image_context':{'scope_id':page.id},'brand_candidates':[{'brand':'Wildberries','method':'ocr-header-wordmark','roi':[10,10,200,50]}]}]
    evaluate_pages(report)
    assert arbitrate(report)==Verdict.SUSPICIOUS
    assert any(e.code=='VISUAL_BRAND_AUTH_MISMATCH' for e in report.reason_codes)
    assert not any(e.code=='PHISHING_FORM_ROUTE' for e in report.reason_codes)


def test_ocr_retains_original_coordinates(monkeypatch):
    import numpy as np
    from types import SimpleNamespace
    from antiphish import ocr
    monkeypatch.setattr(ocr,'status',lambda:{'ready':True})
    def recognize(array,**kw):
        assert array.shape==(450,1800,3)
        return SimpleNamespace(txts=['Wildberries'],scores=[.99],boxes=np.array([[[10,20],[110,20],[110,60],[10,60]]]))
    monkeypatch.setattr(ocr,'_engine',lambda:recognize)
    ocr.reset_budget()
    result=ocr.recognize_layout(Image.new('RGBA',(3600,900),(0,0,0,0)))
    assert result['status']=='COMPLETE' and result['lines'][0]['roi']==[20,40,220,120]


def test_components_api_reports_local_readiness(empty_kb,tmp_path):
    from fastapi.testclient import TestClient
    from antiphish.api import create_app
    response=TestClient(create_app(empty_kb,tmp_path/'history.sqlite')).get('/components')
    assert response.status_code==200
    assert response.json()['laya']['local_only'] is True
    assert response.json()['ocr']['recognizer']=='PP-OCRv5 Cyrillic mobile'


def test_tall_page_keeps_header_wordmark_coordinates(monkeypatch):
    import io
    from antiphish.brandvision import enrich_wordmarks
    def recognize(region):
        assert region.size==(1000,600)
        return {'status':'COMPLETE','lines':[{'text':'Wildberries','score':.99,'roi':[10,20,250,60]}]}
    monkeypatch.setattr('antiphish.ocr.recognize_layout',recognize)
    buffer=io.BytesIO();Image.new('RGB',(1000,3000),'white').save(buffer,'PNG')
    visual={'image_size':[1000,3000],'brand_candidates':[]}
    enrich_wordmarks(visual,buffer.getvalue(),image_role='screenshot')
    assert visual['brand_candidates'][0]['roi']==[10,20,250,60]
