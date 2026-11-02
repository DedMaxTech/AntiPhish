import hashlib,io,sqlite3,urllib.error
from email.message import EmailMessage
from PIL import Image
from fastapi.testclient import TestClient
from antiphish.analyzer import Analyzer
from antiphish.api import create_app
from antiphish.config import Limits
from antiphish.deep import validate_extract
from antiphish.network import FetchResult

def test_forms_receipt_has_one_brand_reason_with_exact_fragments(empty_kb):
 m=EmailMessage();m['From']='Google Forms <forms-receipts-noreply@google.com>';m['Subject']='Wildberries: подарок'
 m.set_content('Google Формы. Wildberries. Ваш бонус готов! Проверьте его по ссылке https://trk.mail.ru/c/sample#be25iy')
 m.add_alternative('<h1>Google Формы</h1><h2>Wildberries</h2><p>Ваш бонус готов. Проверьте его по ссылке.</p><a href="https://trk.mail.ru/c/sample#be25iy">Проверить бонус</a><a href="https://docs.google.com/forms?usp=mail_form_link">Создать форму Google</a>',subtype='html')
 r=Analyzer(empty_kb).analyze(m.as_bytes(),name='message.eml')
 evidence=[e for e in r.reason_codes if e.code=='UNVERIFIED_REWARD_LURE']
 assert len(evidence)==1
 assert evidence[0].details['brand']=='Wildberries'
 assert 'вне известных доменов' in evidence[0].summary
 assert evidence[0].details['identity_comparison']['sender_domain']=='google.com'
 assert evidence[0].details['identity_comparison']['action_hosts']==['trk.mail.ru']
 assert evidence[0].context['selection']=='exact-text'
 assert any('бонус' in h['text'] for h in evidence[0].context['highlights'])
 assert '#be25iy' in evidence[0].context['destinations'][0]

def test_custom_ocr_and_qr_independent_and_request_local(empty_kb,monkeypatch):
 calls=[]
 monkeypatch.setattr('antiphish.ocr.recognize',lambda image:(calls.append('ocr') or ('Safe picture','COMPLETE')))
 monkeypatch.setattr('antiphish.qr.decode',lambda image:(calls.append('qr') or []))
 buffer=io.BytesIO();Image.new('RGB',(80,80),'white').save(buffer,'PNG')
 a=Analyzer(empty_kb)
 first=a.analyze(buffer.getvalue(),name='picture.png',profile='custom',options={'ocr':False,'qr':True})
 assert calls==['qr']
 assert first.configuration['components']['ocr'] is False
 calls.clear()
 a.analyze(buffer.getvalue(),name='picture.png',profile='quality')
 assert calls==['ocr','qr']

def test_models_and_databases_can_be_disabled(empty_kb,monkeypatch):
 monkeypatch.setattr('antiphish.analyzer.optional_deep_analysis',lambda *a,**k:(_ for _ in ()).throw(AssertionError('Disabled model called')))
 a=Analyzer(empty_kb)
 data=b'ordinary mail'
 with sqlite3.connect(empty_kb) as c:
  c.execute('INSERT INTO known_hashes VALUES(?,?,?,?,?,?,?)',(hashlib.sha256(data).hexdigest(),'txt','PHISHING','test',None,None,'user-confirmed'))
 r=a.analyze(data,name='sample.txt',profile='custom',options={'hash_samples':False,'llm':False,'siglip':False,'logo_references':False})
 assert r.verdict.value=='NOT_DETECTED'
 assert a.analyze(data,name='sample.txt').verdict.value=='PHISHING'

def test_model_rejects_instrumentation_and_brand_only_quote():
 bad={'impersonation':True,'credential_request':True,'payment_change':False,'evidence_spans':['Google Формы'],'rationale':'Suspicious antiphish address'}
 assert validate_extract(bad)[0] is False
 bad['rationale']='Подмена сервиса'
 assert validate_extract(bad)[0] is False
 bad['evidence_spans']=['Введите пароль на внешнем сайте']
 assert validate_extract(bad)[0] is True

def test_transparent_logo_retains_black_content_on_white():
 from antiphish.deep import _model_image
 image=Image.new('RGBA',(10,10),(0,0,0,0));image.putpixel((5,5),(0,0,0,255))
 buffer=io.BytesIO();image.save(buffer,'PNG')
 actual=_model_image(buffer.getvalue())
 assert actual.getpixel((0,0))==(255,255,255)
 assert actual.getpixel((5,5))==(0,0,0)

def test_missing_browser_image_explains_failed_navigation(empty_kb):
 def unavailable(url,limits):
  raise urllib.error.HTTPError(url,401,'Unauthorized',{},None)
 r=Analyzer(empty_kb).analyze('https://docs.google.com/forms/private',network='browser',browser_confirmation='I_UNDERSTAND',profile='custom',fetcher=unavailable,options={'llm':False,'siglip':True,'logo_references':False})
 model=next(x for x in r.model_evidence if x.get('status')=='NO_IMAGE')
 assert model['network_mode']=='browser'
 assert '401' in '\n'.join(model['unavailable_sources'])
 assert 'не отсутствие бренда' in model['note']

def test_bundled_logo_gallery_integrity_and_fallback(tmp_path,monkeypatch):
 import json
 from antiphish import config
 from antiphish.brands import load_brands
 from antiphish.policy import official_host
 from antiphish.urltools import normalize_url
 monkeypatch.setattr(config,'MODEL_DIR',tmp_path)
 index=config.logo_index_path()
 metadata=json.loads(index.with_suffix('.json').read_text(encoding='utf8'))
 assert metadata['index_sha256']==hashlib.sha256(index.read_bytes()).hexdigest()
 rows=metadata['references']; assert 50<=len({r['brand'] for r in rows})<=100
 brands={b['name']:b for b in load_brands()}
 for row in rows:
  assert row['reviewed'] is True
  assert official_host(normalize_url(row['source_url']).host,brands[row['brand']]['domains'])
  assert row['sha256']==hashlib.sha256((index.parent/row['path']).read_bytes()).hexdigest()

def test_google_service_footer_is_not_followed_and_401_is_specific(empty_kb):
 calls=[]
 def fetch(url,limits):
  calls.append(url)
  if 'private' in url:raise urllib.error.HTTPError(url,401,'Unauthorized',{},None)
  return FetchResult(b'<a href="https://docs.google.com/forms?usp=x">Create a form</a><a href="https://docs.google.com/forms/private">Open</a>',url,[url],'text/html','200')
 r=Analyzer(empty_kb).analyze('https://start.example/',network='http',fetcher=fetch)
 assert not any('forms?usp' in x for x in calls)
 error=next(x for x in r.network_activity if x['status']=='FAILED')
 assert error['http_status']==401 and 'авторизация' in error['error_message']
 assert any(x.get('http_status')==401 and x['kind']=='failed-navigation' for x in r.routes)

def test_visual_input_keeps_target_page_not_google_auth(empty_kb,monkeypatch):
 output=io.BytesIO();Image.new('RGB',(90,90),'white').save(output,'PNG')
 def fetch(url,limits):
  body=b'<h1>Wildberries</h1><a href="https://accounts.google.com/login">Login</a>' if 'start' in url else b'<h1>Google</h1><form><input type=password></form>'
  return FetchResult(body,url,[url],'text/html','200',screenshot=output.getvalue())
 monkeypatch.setattr('antiphish.analyzer.optional_deep_analysis',lambda *a,**k:([{'model':'SigLIP2-test','suspicious':False}],[]))
 r=Analyzer(empty_kb,Limits(max_network_pages=2)).analyze('https://start.example/',profile='custom',network='http',fetcher=fetch,options={'ocr':False,'qr':False,'siglip':True})
 assert next(m for m in r.model_evidence if m['model']=='SigLIP2-test')['image_context']['url']=='https://start.example/'

def test_knowledge_existing_rows_edit_delete_undo_and_file_import(empty_kb,tmp_path):
 c=TestClient(create_app(empty_kb,tmp_path/'history.sqlite'))
 digest='7'*64
 assert c.post('/knowledge/entries/hashes',json={'value':digest,'source':'confirmed demo'}).status_code==200
 listing=c.get('/knowledge/entries/hashes?q='+digest).json()
 assert listing['total']==1
 row=listing['rows'][0]
 changed=c.patch('/knowledge/entries/hashes/'+str(row['id']),json={'label':'unreviewed'}).json()
 assert c.get('/knowledge/entries/hashes/'+str(row['id'])).json()['provenance']=='provider-labelled-phishing-sample'
 assert c.post('/knowledge/undo/'+changed['change_id']).status_code==200
 deleted=c.delete('/knowledge/entries/hashes/'+str(row['id'])).json()
 assert c.get('/knowledge/entries/hashes').json()['total']==0
 assert c.post('/knowledge/undo/'+deleted['change_id']).status_code==200
 assert c.get('/knowledge/entries/hashes').json()['total']==1
 body=b'<h1>Workspace</h1><form><input type=password></form>'
 added=c.post('/knowledge/import-file',files={'file':('sample.html',body)},data={'label':'phishing','learn_forms':'true'}).json()
 assert added['selected_pages']==1
 assert c.get('/knowledge/entries/templates').json()['total']==1
 assert len(c.get('/reviews').json()['samples'])==1

def test_raw_urls_and_text_available_explicitly_and_options_validated(empty_kb,tmp_path):
 c=TestClient(create_app(empty_kb,tmp_path/'history.sqlite'))
 blob=b'<p>Open document</p><a href="https://example.net/path?token=private-secret-value#short">Open</a>'
 response=c.post('/analyze/file',files={'file':('sample.html',blob)},data={'profile':'custom','options':'{"ocr":false,"qr":false,"llm":false,"siglip":false,"logo_references":false}'}).json()
 raw=c.get('/reports/'+response['report_id']+'/raw-urls').json()
 assert any('private-secret-value' in x['full'] for x in raw['urls'])
 assert 'private-secret-value' not in str(response['report']['urls'])
 assert c.get('/reports/'+response['report_id']+'/text').json()['available']
 assert c.post('/analyze',json={'source':'https://example.net','profile':'custom','options':{'unknown':True}}).status_code==422
 assert c.get('/openapi.json').status_code==200

def test_visual_preview_exists_even_with_ocr_and_qr_disabled(empty_kb,tmp_path,monkeypatch):
 monkeypatch.setattr('antiphish.analyzer.optional_deep_analysis',lambda *a,**k:([{'model':'SigLIP2-test','suspicious':False}],[]))
 output=io.BytesIO();Image.new('RGB',(90,90),'white').save(output,'PNG')
 c=TestClient(create_app(empty_kb,tmp_path/'history.sqlite'))
 result=c.post('/analyze/file',files={'file':('logo.png',output.getvalue())},data={'profile':'custom','options':'{"ocr":false,"qr":false,"siglip":true}'}).json()
 digest=result['report']['model_evidence'][0]['image_context']['artifact_id']
 assert c.get('/reports/'+result['report_id']+'/artifacts/'+digest).status_code==200
 assert 'model_image' not in result['report']

def test_selected_page_template_survives_changed_email_headers(empty_kb,tmp_path):
 c=TestClient(create_app(empty_kb,tmp_path/'history.sqlite'))
 def source(subject):
  m=EmailMessage();m['Subject']=subject;m.set_content('Document')
  m.add_alternative('<h1>Workspace access</h1><form><input type=password name=pass></form>',subtype='html')
  return m.as_bytes()
 first=c.post('/analyze/file',files={'file':('sample.eml',source('first'))}).json()
 assert first['report']['verdict']=='NOT_DETECTED'
 saved=c.post('/reviews',json={'report_id':first['report_id'],'label':'phishing','page_ids':[first['report']['pages'][0]['id']]}).json()
 assert saved['selected_pages']==1
 changed=c.post('/analyze/file',files={'file':('changed.eml',source('second'))}).json()['report']
 assert changed['verdict']=='SUSPICIOUS'
 assert any(e['code']=='CAMPAIGN_TEMPLATE_MATCH' for e in changed['reason_codes'])

def test_text_classifier_switch_uses_local_default_without_env(empty_kb,monkeypatch):
 calls=[]
 monkeypatch.delenv('ANTIPHISH_TEXT_MODEL_DIR',raising=False)
 monkeypatch.setattr('antiphish.textmodel.score',lambda text,path:(calls.append(path) or {'model':'test-classifier','suspicious':False}))
 m=EmailMessage();m.set_content('Ordinary message')
 a=Analyzer(empty_kb)
 a.analyze(m.as_bytes(),name='sample.eml')
 assert not calls
 r=a.analyze(m.as_bytes(),name='sample.eml',profile='custom',options={'text_model':True})
 assert len(calls)==1 and calls[0].name=='phishing-scam-detector-base'
 assert r.configuration['runtime']['text_classifier']['enabled'] is True

def test_individual_feed_can_be_disabled(empty_kb):
 from antiphish.reputation import Feed,install_snapshot
 install_snapshot(empty_kb.with_suffix('.reputation.sqlite'),Feed('openphish','https://feed.example','text','verified','test'),['https://sample.example/bad'])
 a=Analyzer(empty_kb)
 assert a.analyze('https://sample.example/bad').verdict.value=='PHISHING'
 assert a.analyze('https://sample.example/bad',profile='custom',options={'feed_openphish':False}).verdict.value=='NOT_DETECTED'

def test_foreign_website_cannot_poison_local_knowledge(empty_kb,tmp_path):
 c=TestClient(create_app(empty_kb,tmp_path/'history.sqlite'))
 request={'value':'https://sample.example/bad','source':'test'}
 assert c.post('/knowledge/entries/iocs',json=request,headers={'Origin':'https://foreign.example'}).status_code==403
 assert c.get('/knowledge/entries/iocs').json()['total']==0
 assert c.post('/knowledge/entries/iocs',json=request,headers={'Origin':'http://testserver'}).status_code==200

def test_embedded_image_reaches_visual_model_without_ocr_qr(empty_kb,monkeypatch):
 received=[]
 monkeypatch.setattr('antiphish.analyzer.optional_deep_analysis',lambda *a,**k:(received.append(k['image_bytes']) or ([{'model':'visual-test','suspicious':False}],[])))
 picture=io.BytesIO();Image.new('RGBA',(80,80),(0,0,0,0)).save(picture,'PNG')
 m=EmailMessage();m.set_content('Logo attached');m.add_attachment(picture.getvalue(),maintype='image',subtype='png',filename='logo.png')
 report=Analyzer(empty_kb).analyze(m.as_bytes(),name='image.eml',profile='custom',options={'ocr':False,'qr':False,'siglip':True})
 assert received and received[0]
 assert report.model_image
 assert report.model_evidence[0]['image_context']['artifact_id']

def test_forwarded_header_context_does_not_use_parent_sender(empty_kb):
 child=EmailMessage();child['From']='sender@first.example';child['Reply-To']='reply@other.example';child.set_content('Forwarded text')
 parent=EmailMessage();parent['From']='parent@company.example';parent.set_content('See attached');parent.add_attachment(child)
 report=Analyzer(empty_kb).analyze(parent.as_bytes(),name='forward.eml')
 finding=next(e for e in report.reason_codes if e.code=='FROM_REPLYTO_MISMATCH')
 assert 'sender@first.example' in finding.context['text_excerpt']
 assert 'parent@company.example' not in finding.context['text_excerpt']

