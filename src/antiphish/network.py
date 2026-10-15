from __future__ import annotations

import ssl
import socket
import http.client
import time
import subprocess
import threading
import os
from pathlib import Path
from urllib.parse import unquote
import urllib.error
import urllib.request
from dataclasses import dataclass, field, replace

from .config import Limits
from .urltools import is_public_host, normalize_url, resolve_redirect


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, *, addresses, **kwargs):
        super().__init__(host, **kwargs)
        self.addresses = addresses

    def connect(self):
        error = None
        deadline = time.monotonic() + self.timeout
        for address in self.addresses:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Connection time budget reached")
                self.sock = socket.create_connection((address, self.port), remaining)
                self.sock.settimeout(max(.01,deadline-time.monotonic()))
                return
            except OSError as exc:
                error = exc
        raise error or OSError("No public address")


class PinnedHTTPSConnection(PinnedHTTPConnection):
    default_port = 443

    def __init__(self, host, *, addresses, context=None, check_hostname=None, **kwargs):
        super().__init__(host, addresses=addresses, **kwargs)
        self.context = context or ssl.create_default_context()

    def connect(self):
        super().connect()
        # Connect to the address we checked, but verify TLS and send SNI for
        # the original hostname. No second DNS lookup / environment proxy.
        self.sock = self.context.wrap_socket(self.sock, server_hostname=self.host)


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, addresses):
        super().__init__()
        self.addresses = addresses

    def http_open(self, request):
        return self.do_open(lambda host, **kw: PinnedHTTPConnection(host, addresses=self.addresses, **kw), request)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, addresses):
        super().__init__(context=ssl.create_default_context())
        self.addresses = addresses

    def https_open(self, request):
        return self.do_open(lambda host, **kw: PinnedHTTPSConnection(host, addresses=self.addresses, **kw), request, context=self._context)


@dataclass(slots=True)
class FetchResult:
    body: bytes
    final_url: str
    chain: list[str]
    content_type: str
    status: str
    navigation_chain: list[str] = field(default_factory=list, repr=False)
    warnings: list[str] = field(default_factory=list)
    charset: str | None = None
    interactions: list[dict] = field(default_factory=list)
    screenshot: bytes = field(default=b"", repr=False)


class _BrowserDeadline:
    """Kill only this driver's browser children; keep the event loop alive."""
    def __init__(self, playwright, seconds):
        # The app's browser backend is Windows Edge. A driver failure must
        # never kill a user's existing Edge window or another analysis.
        transport = playwright._impl_obj._connection._transport
        self.pid = transport._proc.pid
        import psutil
        self.created = psutil.Process(self.pid).create_time()
        self.timer = threading.Timer(max(1, seconds), self.stop)
        self.timer.daemon = True

    def stop(self):
        import psutil
        try:
            driver = psutil.Process(self.pid)
            if driver.create_time() != self.created:
                return
            # Killing the driver used to leave a running greenlet/asyncio loop
            # behind, breaking every subsequent browser analysis in the thread.
            children = driver.children(recursive=True)
            for child in reversed(children):
                try:
                    child.kill()
                except psutil.Error:
                    pass
        except psutil.Error:
            pass

    def __enter__(self):
        self.timer.start()
        return self

    def __exit__(self, *exc):
        self.timer.cancel()


def safe_http_get(url: str, limits: Limits) -> FetchResult:
    current = normalize_url(url)
    if "TOKENIZED_URL" in current.flags and "ACTION_URL" in current.flags:
        raise ValueError("tokenized action URLs are not fetched")
    chain: list[str] = []
    raw_chain: list[str] = []
    deadline = time.monotonic() + limits.network_timeout_seconds
    for _ in range(limits.max_redirects + 1):
        if "TOKENIZED_URL" in current.flags and "ACTION_URL" in current.flags:
            raise ValueError("tokenized action redirect is not fetched")
        allowed, _addresses = is_public_host(current.host)
        if not allowed:
            raise ValueError(f"SSRF protection rejected host {current.host}")
        chain.append(current.redacted)
        raw_chain.append(current.normalized)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect, PinnedHTTPHandler(_addresses), PinnedHTTPSHandler(_addresses))
        request = urllib.request.Request(current.normalized.split("#", 1)[0], headers={"User-Agent": "AntiPhish/2.0 safe-static-fetch", "Accept-Encoding": "identity", "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.1"}, method="GET")
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP time budget reached")
            response = opener.open(request, timeout=remaining)
        except urllib.error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308} and exc.headers.get("Location"):
                current = normalize_url(resolve_redirect(current.normalized, exc.headers["Location"]))
                continue
            raise
        with response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > limits.max_http_bytes:
                raise ValueError("HTTP body exceeds configured limit")
            if hasattr(response,"read1"):
                chunks, size = [], 0
                while size <= limits.max_http_bytes:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("HTTP body time budget reached")
                    raw_socket = getattr(getattr(getattr(response,"fp",None),"raw",None),"_sock",None)
                    if raw_socket is not None:
                        raw_socket.settimeout(remaining)
                    chunk = response.read1(min(65536,limits.max_http_bytes+1-size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                body = b"".join(chunks)
            else:
                body = response.read(limits.max_http_bytes + 1)
            if len(body) > limits.max_http_bytes:
                raise ValueError("HTTP body exceeds configured limit")
            ctype = response.headers.get_content_type()
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise ValueError("Unexpected compressed HTTP response")
            return FetchResult(body=body, final_url=current.normalized, chain=chain, content_type=ctype, status=str(response.status),navigation_chain=raw_chain,charset=response.headers.get_content_charset())
    raise ValueError("redirect limit reached")


def browser_executable() -> str | None:
    configured = os.environ.get('ANTIPHISH_BROWSER_EXECUTABLE')
    if configured:
        if not Path(configured).is_file():
            raise ValueError('Configured browser executable not found')
        return configured
    edge = Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
    return str(edge) if os.name == 'nt' and edge.exists() else None


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
    started = time.monotonic()
    # Start at the URL resolved by the pinned transport. A synthetic browser
    # 302 can bypass Playwright interception for the redirected request.
    initial = safe_http_get(target.normalized, limits)
    if initial.content_type not in {'text/html', 'application/xhtml+xml'}:
        # Documents are handled by their bounded static parser, rather than
        # mistaking a browser's own PDF viewer for the attacker's login form.
        return initial
    with sync_playwright() as pw, _BrowserDeadline(pw, limits.max_network_seconds-(time.monotonic()-started)):
        browser = pw.chromium.launch(executable_path=browser_executable(), headless=True, args=["--disable-extensions", "--disable-sync", "--disable-background-networking", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
        context = browser.new_context(service_workers="block", accept_downloads=False)
        context.set_default_timeout(1500)
        context.add_init_script("for(const key of ['RTCPeerConnection','webkitRTCPeerConnection']){try{Object.defineProperty(globalThis,key,{value:undefined,writable:false,configurable:false})}catch(e){}}")
        page = context.new_page()
        chain: list[str] = list(initial.chain)
        navigation_chain: list[str] = list(initial.navigation_chain or [target.normalized, initial.final_url])
        warnings: list[str] = []
        requests_seen = 0
        bytes_seen = 0
        response_cache = {initial.final_url: initial}
        pending_navigation = None
        blocked_submissions = 0
        probe_active = False
        probe_markers, probe_identity, probe_origin, probe_form = {}, "", "", ""
        interactions = []

        def abort(route, message=None):
            if message and message not in warnings:
                warnings.append(message)
            route.abort()

        def route_handler(route):
            nonlocal requests_seen, bytes_seen, pending_navigation, blocked_submissions
            request = route.request
            if probe_active:
                # Even GET is blocked once we fill a canary. A URL query,
                # image or beacon can otherwise carry the synthetic secret.
                try:
                    payload = unquote(request.url + "\n" + (request.post_data or ""))
                except Exception:
                    payload = unquote(request.url)
                types = sorted({typ for marker, typ in probe_markers.items() if marker in payload and typ != "email"})
                if types and len(interactions) < 32:
                    try:
                        recipient = normalize_url(request.url)
                        interactions.append({"destination": recipient.redacted, "destination_host": recipient.host, "method": request.method.lower(), "sensitive_types": types, "page_url": probe_origin, "identity_text": probe_identity, "form_index": probe_form, "synthetic_only": True, "transmitted": False})
                    except ValueError:
                        pass
                blocked_submissions += 1
                abort(route)
                return
            if request.method != "GET":
                blocked_submissions += 1
                abort(route)
                return
            if request.resource_type in {"websocket", "eventsource", "media", "font"}:
                abort(route)
                return
            try:
                requests_seen += 1
                remaining = limits.max_network_seconds - (time.monotonic() - started)
                if requests_seen > 80 or remaining <= 0 or bytes_seen >= limits.max_total_extracted_bytes:
                    abort(route, "Browser resource budget reached")
                    return
                fetched = response_cache.pop(request.url, None) or safe_http_get(request.url, replace(limits,network_timeout_seconds=min(remaining,limits.network_timeout_seconds)))
                bytes_seen += len(fetched.body)
                if bytes_seen > limits.max_total_extracted_bytes:
                    abort(route, "Browser byte budget reached")
                    return
                if request.is_navigation_request():
                    chain.extend(fetched.chain)
                    navigation_chain.extend(fetched.navigation_chain or [request.url, fetched.final_url])
                    if normalize_url(request.url).normalized != fetched.final_url:
                        if request.frame != page.main_frame:
                            abort(route, "Redirected frame was not rendered")
                            return
                        response_cache[fetched.final_url] = fetched
                        pending_navigation = fetched.final_url
                        # The outer loop opens this as a fresh intercepted
                        # navigation, giving scripts their correct origin.
                        route.fulfill(status=200,body="<html></html>",content_type="text/html")
                        return
                ctype = fetched.content_type + ("; charset=" + fetched.charset if fetched.charset else "")
                rendered_body = fetched.body
                if "html" in fetched.content_type:
                    from .extractors import _decode_html
                    rendered_body = _decode_html(fetched.body, fetched.charset).encode("utf-8")
                    ctype = fetched.content_type + "; charset=utf-8"
                route.fulfill(status=int(fetched.status), body=rendered_body, content_type=ctype)
            except Exception as exc:
                abort(route, "Browser GET failed: " + type(exc).__name__)
                return

        context.route("**/*", route_handler)
        # A routed socket never connects unless connect_to_server() is called.
        # Leave it disconnected; close() can hang on an unfinished handshake.
        context.route_web_socket("**/*", lambda ws: None)
        page.on("dialog", lambda dialog: dialog.dismiss())
        page.on("popup", lambda popup: popup.close())
        try:
            destination = initial.final_url
            for _ in range(limits.max_redirects + 1):
                pending_navigation = None
                remaining = limits.max_network_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError("Browser navigation time budget reached")
                response = page.goto(destination, wait_until="domcontentloaded", timeout=int(min(remaining,limits.network_timeout_seconds) * 1000))
                if response is None:
                    raise ValueError("Browser navigation did not produce a response")
                page.wait_for_timeout(min(750,max(1,int(remaining * 1000))))
                if pending_navigation is None:
                    break
                destination = pending_navigation
            else:
                warnings.append("Browser navigation limit reached")
            final = normalize_url(page.url)
            chain.extend([target.redacted, final.redacted])
            navigation_chain.append(final.normalized)
            body = page.content().encode("utf-8")
            screenshot = b""
            # Enforce the traffic lock BEFORE touching any input. Scripts may
            # react to fill(), without waiting for the submit button.
            probe_active = True
            def prepare(markers, origin, identity, form_index):
                nonlocal probe_markers, probe_origin, probe_identity, probe_form
                probe_markers, probe_origin, probe_identity, probe_form = markers, origin, identity, form_index
            try:
                from .browserprobe import probe_forms
                body, screenshot, steps = probe_forms(page, prepare, started + limits.max_network_seconds)
                if steps and not interactions:
                    warnings.append("Authentication probing stopped before an observable secret recipient")
                if not screenshot and time.monotonic()-started < limits.max_network_seconds:
                    screenshot = page.screenshot(type="png", timeout=1500, animations="disabled")
            except Exception as exc:
                warnings.append("Client-side form probing incomplete: " + type(exc).__name__)
            if len(body) > limits.max_http_bytes:
                raise ValueError("Browser DOM exceeds configured byte limit")
            status = str(response.status)
            if blocked_submissions:
                warnings.append(f"Browser blocked {blocked_submissions} non-GET requests")
        finally:
            # After a deadline the browser is already dead; allow Playwright's
            # context manager to finish cleaning its driver and event loop.
            try:
                context.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass
    return FetchResult(body=body, final_url=final.normalized, chain=list(dict.fromkeys(chain)), content_type="text/html", status=status,navigation_chain=list(dict.fromkeys(navigation_chain)),warnings=warnings,charset="utf-8",interactions=interactions,screenshot=screenshot)
