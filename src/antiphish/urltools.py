from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

import idna

try:
    import tldextract
except ImportError:  # pragma: no cover
    tldextract = None

_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=()) if tldextract else None

from .utils import TOKEN_KEYS, redact_value


URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
ACTION_PATH_RE = re.compile(r"(?i)/(?:unsubscribe|confirm|verify|activate|reset|magic|invite|login)(?:/|$)")
SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "clck.ru", "vk.cc", "is.gd", "cutt.ly", "shorturl.at"
}


@dataclass(frozen=True, slots=True)
class NormalizedUrl:
    original: str
    normalized: str
    host: str
    unicode_host: str
    registered_domain: str
    redacted: str
    flags: tuple[str, ...]


def _extract_registered_domain(host: str) -> str:
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if _TLD_EXTRACTOR:
        ext = _TLD_EXTRACTOR(host)
        if ext.suffix:
            return ".".join(p for p in (ext.domain, ext.suffix) if p)
        # Private/reserved/internal suffixes are absent from PSL. Treat the
        # last two labels as the site boundary instead of collapsing every
        # host ending in `.example` or `.internal` into one site.
        parts = host.rsplit(".", 2)
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    parts = host.rsplit(".", 2)
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def normalize_url(raw: str) -> NormalizedUrl:
    value = raw.strip().strip("<>[](){}.,;\"'")
    split = urlsplit(value)
    if split.scheme.lower() not in {"http", "https"}:
        raise ValueError("only http/https URLs are supported")
    if not split.hostname:
        raise ValueError("URL has no host")
    flags: list[str] = []
    unicode_host = split.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(unicode_host)
        ascii_host = unicode_host
    except ValueError:
        try:
            ascii_host = idna.encode(unicode_host, uts46=True).decode("ascii").lower()
        except idna.IDNAError as exc:
            raise ValueError(f"invalid IDN host: {exc}") from exc
    if "xn--" in ascii_host:
        flags.append("IDN_PUNYCODE")
    scripts = {"latin" if "LATIN" in unicodedata.name(c, "") else "cyrillic" if "CYRILLIC" in unicodedata.name(c, "") else "other" for c in unicode_host if c.isalpha()}
    if "latin" in scripts and "cyrillic" in scripts:
        flags.append("MIXED_SCRIPT_HOST")
    try:
        ip = ipaddress.ip_address(ascii_host)
        flags.append("IP_LITERAL")
        if not ip.is_global:
            flags.append("NON_PUBLIC_IP")
    except ValueError:
        pass
    port = split.port
    if port and port not in {80, 443}:
        flags.append("NON_STANDARD_PORT")
    if split.username or split.password:
        flags.append("USERINFO_IN_URL")
    reg = _extract_registered_domain(ascii_host)
    if reg in SHORTENERS:
        flags.append("URL_SHORTENER")
    if ACTION_PATH_RE.search(split.path):
        flags.append("ACTION_URL")
    query = parse_qsl(split.query, keep_blank_values=True)
    if any(TOKEN_KEYS.search(k) or (len(v) >= 24 and re.search(r"[A-Za-z].*\d|\d.*[A-Za-z]", v)) for k, v in query):
        flags.append("TOKENIZED_URL")
    default_port = (split.scheme.lower() == "https" and port in {None, 443}) or (split.scheme.lower() == "http" and port in {None, 80})
    display_host = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    netloc = display_host if default_port else f"{display_host}:{port}"
    path = quote(split.path or "/", safe="/%:@-._~!$&'()*+,;=")
    normalized = urlunsplit((split.scheme.lower(), netloc, path, urlencode(query, doseq=True), ""))
    redacted_query = urlencode([(k, redact_value(v) if TOKEN_KEYS.search(k) else v) for k, v in query], doseq=True).replace("%2A", "*").replace("%2a", "*")
    redacted = urlunsplit((split.scheme.lower(), netloc, path, redacted_query, ""))
    return NormalizedUrl(value, normalized, ascii_host, unicode_host, reg, redacted, tuple(sorted(set(flags))))


def extract_urls(text: str) -> list[str]:
    return [m.group(0).rstrip(".,;:!?)\"]}") for m in URL_RE.finditer(text)]


def is_public_host(host: str) -> tuple[bool, list[str]]:
    try:
        addresses = sorted({info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    except OSError:
        return False, []
    if not addresses:
        return False, []
    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_global:
                return False, addresses
        except ValueError:
            return False, addresses
    return True, addresses


def same_site(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return _extract_registered_domain(a.lower()) == _extract_registered_domain(b.lower())


def resolve_redirect(base: str, location: str) -> str:
    return urljoin(base, location)
