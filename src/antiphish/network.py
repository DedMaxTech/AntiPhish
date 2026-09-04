from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

from .config import Limits
from .urltools import is_public_host, normalize_url, resolve_redirect


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(slots=True)
class FetchResult:
    body: bytes
    final_url: str
    chain: list[str]
    content_type: str
    status: str


def safe_http_get(url: str, limits: Limits) -> FetchResult:
    current = normalize_url(url)
    if "TOKENIZED_URL" in current.flags and "ACTION_URL" in current.flags:
        raise ValueError("tokenized action URLs are not fetched")
    chain: list[str] = []
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    for _ in range(limits.max_redirects + 1):
        allowed, _addresses = is_public_host(current.host)
        if not allowed:
            raise ValueError(f"SSRF protection rejected host {current.host}")
        chain.append(current.redacted)
        request = urllib.request.Request(current.normalized, headers={"User-Agent": "AntiPhish/1.0 safe-static-fetch", "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.1"}, method="GET")
        try:
            response = opener.open(request, timeout=limits.network_timeout_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308} and exc.headers.get("Location"):
                current = normalize_url(resolve_redirect(current.normalized, exc.headers["Location"]))
                continue
            raise
        with response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > limits.max_http_bytes:
                raise ValueError("HTTP body exceeds configured limit")
            body = response.read(limits.max_http_bytes + 1)
            if len(body) > limits.max_http_bytes:
                raise ValueError("HTTP body exceeds configured limit")
            ctype = response.headers.get_content_type()
            return FetchResult(body=body, final_url=current.normalized, chain=chain, content_type=ctype, status=str(response.status))
    raise ValueError("redirect limit reached")


def safe_browser_get(url: str, limits: Limits, confirmation: str | None) -> FetchResult:
    if confirmation != "I_UNDERSTAND":
        raise ValueError("browser mode requires --confirm-browser-risk I_UNDERSTAND")
    target = normalize_url(url)
    if "TOKENIZED_URL" in target.flags and "ACTION_URL" in target.flags:
        raise ValueError("tokenized action URLs are not opened in browser mode")
    allowed, _ = is_public_host(target.host)
    if not allowed:
        raise ValueError("SSRF protection rejected initial host")
    from playwright.sync_api import sync_playwright
    edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=edge, headless=True, args=["--disable-extensions", "--disable-sync", "--disable-background-networking"])
        context = browser.new_context(service_workers="block", accept_downloads=False)
        page = context.new_page()
        chain: list[str] = []

        def route_handler(route):
            request = route.request
            if request.method not in {"GET", "HEAD"} or request.resource_type in {"websocket", "xhr", "fetch", "eventsource", "media", "font"}:
                route.abort()
                return
            try:
                parsed = normalize_url(request.url)
                ok, _addresses = is_public_host(parsed.host)
                if not ok:
                    route.abort()
                    return
            except ValueError:
                route.abort()
                return
            route.continue_()

        context.route("**/*", route_handler)
        page.on("dialog", lambda dialog: dialog.dismiss())
        page.on("popup", lambda popup: popup.close())
        response = page.goto(target.normalized, wait_until="domcontentloaded", timeout=int(limits.network_timeout_seconds * 1000))
        page.wait_for_timeout(750)
        final = normalize_url(page.url)
        chain = [normalize_url(r.url).redacted for r in response.request.redirected_from.redirected_from] if False else [target.redacted, final.redacted]
        body = page.content().encode("utf-8")
        if len(body) > limits.max_http_bytes:
            body = body[: limits.max_http_bytes]
        status = str(response.status) if response else "unknown"
        context.close()
        browser.close()
    return FetchResult(body=body, final_url=final.normalized, chain=list(dict.fromkeys(chain)), content_type="text/html", status=status)
