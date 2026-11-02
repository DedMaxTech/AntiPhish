import base64
import io
import json
from email.message import EmailMessage

import pytest
from PIL import Image

from antiphish.analyzer import Analyzer
from antiphish.config import RESOURCE_DIR
from antiphish.models import Verdict
from antiphish.network import FetchResult


def symbol(brand):
    rows=[json.loads(s) for s in (RESOURCE_DIR/'logo-gallery/manifest.jsonl').read_text(encoding='utf-8').splitlines() if s.strip()]
    row=next(r for r in rows if r['brand']==brand)
    return (RESOURCE_DIR/'logo-gallery'/row['path']).read_bytes()


def png(image):
    stream=io.BytesIO();image.save(stream,'PNG');return stream.getvalue()


@pytest.mark.parametrize('size,bg,point',[(36,'#f7f7f7',(400,65)),(70,'white',(80,780)),(110,'#efefef',(600,320))])
def test_avito_symbol_is_localized_without_name_or_ocr(size,bg,point):
    from antiphish.visual import match_image
    logo=Image.open(io.BytesIO(symbol('Авито'))).convert('RGBA').resize((size,size))
    image=Image.new('RGB',(900,1000),bg);image.paste(logo,point,logo)
    found=match_image(png(image))['brand_candidates']
    match=next(c for c in found if c['brand']=='Авито')
    assert not match['method'].startswith('ocr-')
    x1,y1,x2,y2=match['roi']
    assert abs(x1-point[0])<10 and abs(y1-point[1])<10
    assert x2>x1 and y2>y1


def test_remote_mail_logo_without_css_class_is_fetched_and_rendered(empty_kb):
    mail=EmailMessage();mail.set_content('Уровень сервиса')
    mail.add_alternative('''<!doctype html><!-- mail comment --><html><body>
        <img src="https://cdn.example/pixel.gif?token=secret" width="1px">
        <img src="https://cdn.example/CRM/new_logo_2022/avito_logo.png" width="140">
        <h1>Уровень сервиса на Авито</h1></body></html>''',subtype='html')
    calls=[]
    def fetch(url,limits):
        calls.append(url)
        return FetchResult(symbol('Авито'),url,[url],'image/png','200')
    r=Analyzer(empty_kb).analyze(mail.as_bytes(),name='mail.eml',network='http',fetcher=fetch,options={'ocr':False,'qr':False})
    assert calls==['https://cdn.example/CRM/new_logo_2022/avito_logo.png']
    assert r.configuration['local_render']['rendered']==1
    assert r.configuration['local_render']['missing_images']==0
    models=[m for m in r.model_evidence if m.get('model')=='Local-logo-geometry']
    assert any(m['image_context']['image_role']=='mail-render' and m['graphic_matches'] for m in models)
    assert all(m['image_context']['image_source_url'] is None for m in models if m['image_context']['image_role']=='mail-render')
    assert r.verdict==Verdict.NOT_DETECTED


def test_render_has_cid_and_content_location_even_offline(empty_kb):
    mail=EmailMessage();mail.set_content('Обычное уведомление')
    mail.add_alternative('<img src="cid:brand%40mail"><img src="images/symbol.png">',subtype='html')
    part=mail.get_payload()[-1];part.add_related(symbol('Авито'),maintype='image',subtype='png',cid='<brand@mail>',filename='logo.png')
    part.get_payload()[-1]['Content-Location']='images/symbol.png'
    r=Analyzer(empty_kb).analyze(mail.as_bytes(),name='mail.eml',options={'ocr':False,'qr':False})
    assert r.configuration['local_render']['rendered']>=1
    assert r.configuration['local_render']['missing_images']==0
    assert not r.network_activity


def test_failed_asset_is_not_replaced_with_brand_reference(empty_kb):
    body=b'<img src="https://cdn.example/logo.png"><p>Avito</p>'
    def fail(url,limits):raise TimeoutError('Unavailable')
    r=Analyzer(empty_kb).analyze(body,name='mail.html',network='http',fetcher=fail,options={'ocr':False,'qr':False})
    assert r.configuration['local_render']['missing_images']==1
    assert all(not p.render_assets for p in r.pages)
    assert not any(m.get('graphic_matches') for m in r.model_evidence)


def test_same_logo_is_reused_for_every_owner_without_extra_requests(empty_kb):
    from antiphish.extractors import Extracted,extract_html
    from antiphish.config import DEFAULT_LIMITS
    from antiphish.visualassets import enrich_logos
    from antiphish.models import AnalysisReport
    import time
    a=extract_html(b'<img class=logo src="https://cdn.example/logo.png">',DEFAULT_LIMITS,'https://a.example/')
    b=extract_html(b'<img class=logo src="https://cdn.example/logo.png">',DEFAULT_LIMITS,'https://b.example/')
    extracted=Extracted('html','test',0);extracted.pages=a.pages+b.pages;calls=[]
    def fetch(url,limits):calls.append(url);return FetchResult(symbol('Авито'),url,[url],'image/png','200')
    enrich_logos(extracted,AnalysisReport(),fetch,DEFAULT_LIMITS,time.monotonic())
    assert len(calls)==1 and all(p.render_assets and p.visual_images for p in extracted.pages)


def test_regional_cloud_content_is_not_a_verified_password_origin():
    from antiphish.brands import load_brands
    from antiphish.policy import credential_host
    brand=next(b for b in load_brands() if b['name']=='Яндекс')
    assert credential_host('passport.yandex.kz',brand,['password'])
    assert not credential_host('forms.yandex.kz',brand,['password'])
    assert not credential_host('disk.yandex.kz',brand,['password'])


def test_geometry_gallery_and_api_use_the_same_reference_files(empty_kb,tmp_path):
    from antiphish.api import create_app
    from antiphish.logogallery import reviewed_references
    from fastapi.testclient import TestClient
    client=TestClient(create_app(empty_kb,tmp_path/'history.sqlite'))
    gallery=client.get('/knowledge').json()['logo_gallery']
    assert gallery['references']==len(reviewed_references())
    row=gallery['items'][-1]
    assert client.get('/knowledge/logos/'+row['sha256']).status_code==200


def test_css_logo_background_uses_the_same_safe_image_fetch(empty_kb):
    body=b'<div class=logo style="width:100px;height:100px;background:url(/brand.png) no-repeat;background-size:contain"></div>'
    calls=[]
    def fetch(url,limits):
        calls.append(url);return FetchResult(symbol('Авито'),url,[url],'image/png','200')
    r=Analyzer(empty_kb).analyze(body,name='page.html',base_url='https://page.example/',network='http',fetcher=fetch,options={'ocr':False,'qr':False})
    assert calls==['https://page.example/brand.png']
    assert any(m.get('graphic_matches') and m['image_context']['image_role']=='local-render' for m in r.model_evidence)


def test_import_gallery_needs_no_neural_index_and_is_idempotent(tmp_path,monkeypatch):
    from antiphish import config
    from antiphish.logogallery import import_gallery,reviewed_references
    monkeypatch.setattr(config,'MODEL_DIR',tmp_path/'models')
    source=tmp_path/'source';source.mkdir();(source/'icon.png').write_bytes(symbol('Авито'))
    (source/'manifest.jsonl').write_text(json.dumps({'brand':'Авито','path':'icon.png','source_url':'https://avito.ru/','reviewed':True}),encoding='utf-8')
    assert import_gallery(source)['imported']==1
    assert import_gallery(source)['imported']==0
    local=config.MODEL_DIR/'logo-references'
    assert len(reviewed_references(local))==1
    assert not (config.MODEL_DIR/'logo-index.npz').exists()
