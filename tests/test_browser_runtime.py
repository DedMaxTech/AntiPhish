"""Exercise the real browser with synthetic pages and a fully stubbed transport."""
from pathlib import Path

import pytest

from antiphish.config import Limits
from antiphish.network import FetchResult, safe_browser_get
from antiphish.network import browser_executable

def installed_browser():
    from playwright.sync_api import sync_playwright
    configured = browser_executable()
    if configured:
        return Path(configured).is_file()
    with sync_playwright() as pw:
        return Path(pw.chromium.executable_path).is_file()

BROWSER_AVAILABLE = installed_browser()


def test_browser_document_uses_original_bytes_and_content_type(monkeypatch):
    body=b'%PDF-1.7 fixture'
    monkeypatch.setattr('antiphish.network.is_public_host',lambda host:(True,['93.184.216.34']))
    monkeypatch.setattr('antiphish.network.safe_http_get',lambda url,limits:FetchResult(body,url,[url],'application/pdf','200'))
    result=safe_browser_get('https://document-fixture.example/report.pdf',Limits(),'I_UNDERSTAND')
    assert result.body == body
    assert result.content_type == 'application/pdf'


@pytest.mark.skipif(not BROWSER_AVAILABLE, reason="Browser not installed")
def test_browser_redirects_keep_origin_and_block_submissions(monkeypatch):
    calls = []

    def fetch(url, limits):
        calls.append(url)
        if url == "https://browser-fixture.example/start":
            return FetchResult(b"<script>fetch('/submit',{method:'POST',body:'synthetic'}); new WebSocket('wss://socket-fixture.example/'); setTimeout(()=>location.href='/hop',100)</script>", url, [url], "text/html", "200")
        if url == "https://browser-fixture.example/hop":
            final = "https://final-fixture.example/landing"
            return FetchResult(b"<h1>Harmless fixture</h1><script>document.body.dataset.executed=location.hostname; fetch('http://127.0.0.1/private')</script>", final, [url, final], "text/html", "200", navigation_chain=[url, final])
        raise ValueError("No live requests permitted")

    monkeypatch.setattr("antiphish.network.is_public_host", lambda h: (True, ["93.184.216.34"]))
    monkeypatch.setattr("antiphish.network.safe_http_get", fetch)
    result = safe_browser_get("https://browser-fixture.example/start", Limits(), "I_UNDERSTAND")
    assert result.final_url == "https://final-fixture.example/landing"
    assert b'data-executed="final-fixture.example"' in result.body
    assert not any("/submit" in u or "wss:" in u for u in calls)
    assert any("non-GET" in w for w in result.warnings)
    assert any(r['url']=='http://127.0.0.1/private' and r['status']=='FAILED' for r in result.resource_observations)


def test_http_charset_is_used_for_russian_page(empty_kb):
    from antiphish.analyzer import Analyzer
    from antiphish.models import Verdict
    body = "<h1>СберБанк</h1><form action='/send' method=post><input type=password></form>".encode("cp1251")
    def fetch(url, limits):
        return FetchResult(body,url,[url],"text/html","200",charset="windows-1251")
    report = Analyzer(empty_kb).analyze("https://fake.example/login",network="http",fetcher=fetch)
    assert report.verdict == Verdict.PHISHING
    assert "СберБанк" in report.pages[0].claimed_brands


@pytest.mark.skipif(not BROWSER_AVAILABLE, reason="Browser not installed")
@pytest.mark.parametrize("official", [False, True])
def test_multistep_canary_never_leaves_browser(monkeypatch, empty_kb, official):
    from antiphish.analyzer import Analyzer
    from antiphish.models import Verdict
    url = "https://online.sberbank.ru/login" if official else "https://fake-auth.example/login"
    calls = []
    body = """<title>СберБанк</title><h1>СберБанк</h1>
    <form onsubmit='event.preventDefault()'><input type=email id=mail>
    <button type=button onclick="document.getElementById('second').hidden=false;this.hidden=true">Далее</button>
    <div id=second hidden><input type=password id=pw><button type=button onclick="fetch('/collect',{method:'POST',body:document.getElementById('pw').value})">Войти</button></div></form>""".encode()
    def fetch(raw, limits):
        calls.append(raw)
        if raw == url:
            return FetchResult(body, raw, [raw], "text/html", "200")
        raise AssertionError("No live traffic permitted")
    monkeypatch.setattr("antiphish.network.is_public_host", lambda h: (True, ["93.184.216.34"]))
    monkeypatch.setattr("antiphish.network.safe_http_get", fetch)
    observed = []
    def render(raw, limits):
        result = safe_browser_get(raw, limits, "I_UNDERSTAND")
        observed.append(result)
        return result
    report = Analyzer(empty_kb).analyze(url, network="browser", browser_confirmation="I_UNDERSTAND", fetcher=render, profile="fast")
    assert observed[0].interactions
    assert observed[0].interactions[0]["sensitive_types"] == ["password"]
    assert observed[0].interactions[0]["transmitted"] is False
    assert calls == [url]
    assert "DYNAMIC_SECRET_COLLECTOR" in {e.code for e in report.reason_codes}
    assert report.verdict == (Verdict.NOT_DETECTED if official else Verdict.PHISHING)


@pytest.mark.skipif(not BROWSER_AVAILABLE, reason="Browser not installed")
def test_input_event_get_exfiltration_is_observed_but_blocked(monkeypatch):
    calls = []
    url = "https://fake-auth.example/login"
    body = b"<form><input type=password oninput=\"fetch('/pixel?pw='+this.value)\"><button type=button>Continue</button></form>"
    def fetch(raw, limits):
        calls.append(raw)
        return FetchResult(body, raw, [raw], "text/html", "200")
    monkeypatch.setattr("antiphish.network.is_public_host", lambda h: (True, ["93.184.216.34"]))
    monkeypatch.setattr("antiphish.network.safe_http_get", fetch)
    result = safe_browser_get(url, Limits(), "I_UNDERSTAND")
    assert calls == [url]
    assert any(i["method"] == "get" and i["sensitive_types"] == ["password"] for i in result.interactions)
    assert all(i["transmitted"] is False for i in result.interactions)


def test_analytics_cannot_inherit_unrelated_password_reads(empty_kb):
    from antiphish.analyzer import Analyzer
    from antiphish.models import Verdict
    body = b"<h1>Microsoft</h1><form action='https://login.microsoft.com'><input id=pw type=password></form><script>const pw=document.getElementById('pw').value; fetch('https://analytics.example/pixel',{body:'ordinary page view'});</script>"
    report = Analyzer(empty_kb).analyze(body, name="login.html", base_url="https://custom.example/login")
    assert report.verdict == Verdict.NOT_DETECTED


@pytest.mark.skipif(not BROWSER_AVAILABLE, reason="Browser not installed")
def test_stalled_browser_has_a_hard_deadline(monkeypatch):
    import time
    url = "https://stall-fixture.example/"
    monkeypatch.setattr("antiphish.network.is_public_host", lambda h: (True, ["93.184.216.34"]))
    monkeypatch.setattr("antiphish.network.safe_http_get", lambda raw, limits: FetchResult(b"<script>while(true){}</script>",raw,[raw],"text/html","200"))
    started = time.monotonic()
    with pytest.raises(Exception):
        safe_browser_get(url, Limits(max_network_seconds=3, network_timeout_seconds=3), "I_UNDERSTAND")
    assert time.monotonic() - started < 12
    monkeypatch.setattr('antiphish.network.safe_http_get', lambda raw, limits: FetchResult(b'<h1>After timeout</h1>',raw,[raw],'text/html','200'))
    healthy = safe_browser_get('https://healthy-fixture.example/', Limits(max_network_seconds=8), 'I_UNDERSTAND')
    assert b'After timeout' in healthy.body
