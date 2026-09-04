from __future__ import annotations

import socket

import pytest

from antiphish.urltools import is_public_host, normalize_url, same_site


def test_idn_and_mixed_script_flags():
    url = normalize_url("https://sberbаnk.ru/login?token=abcdefghijklmnopqrstuvwxyz1234")  # Cyrillic а
    assert "IDN_PUNYCODE" in url.flags
    assert "MIXED_SCRIPT_HOST" in url.flags
    assert "TOKENIZED_URL" in url.flags


def test_redacts_token_but_preserves_normalized_for_matching():
    url = normalize_url("https://example.ru/reset?token=abcdefghijklmnop")
    assert "abcdefghijklmnop" in url.normalized
    assert "ab***op" in url.redacted


@pytest.mark.parametrize("value", ["file:///etc/passwd", "javascript:alert(1)", "ftp://example.com/a"])
def test_forbidden_schemes(value):
    with pytest.raises(ValueError):
        normalize_url(value)


def test_private_dns_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))])
    assert is_public_host("attacker.example")[0] is False


def test_public_suffix_offline():
    assert same_site("login.company.co.uk", "company.co.uk")
    assert not same_site("company.co.uk.evil.test", "company.co.uk")


def test_ipv6_host_keeps_brackets():
    assert normalize_url("https://[2606:4700:4700::1111]/x").normalized.startswith("https://[")
