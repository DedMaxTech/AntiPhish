"""Static active-content inspection: no JS/VBA execution, no remote template load."""
from __future__ import annotations

import hashlib
import re
import time
import zlib
from contextvars import ContextVar

_budget = ContextVar('antiphish_active_budget', default=None)


def reset_budget():
    _budget.set({'seconds':0.0})

from .htmlanalysis import decode_script_literals
from .urltools import extract_urls, normalize_url


def script_facts(code: str, source: str) -> dict:
    decoded = decode_script_literals(code, cap=250000)
    urls = []
    for value in extract_urls(decoded)[:50]:
        try:
            urls.append(normalize_url(value).redacted)
        except ValueError:
            pass
    # Features are observations, not an executable rule or a standalone proof.
    features = {
        'auto_execution': r'(?i)\b(?:AutoOpen|Document_Open|Workbook_Open|app\.setTimeOut)\b',
        'network_submission': r'(?i)(?:submitForm\s*\(|XMLHTTP|WinHttp|URLDownloadToFile|fetch\s*\(|sendBeacon\s*\()',
        'field_read': r'(?i)(?:getField\s*\(|\.value\b|FormFields)',
        'secret_field_read': r'''(?i)getField\s*\(\s*['"][^'"]*(?:password|passwd|парол|\botp\b|cvv|cvc|seed|private.?key)[^'"]*['"]''',
        'process_launch': r'(?i)(?:launchURL\s*\(|Shell\s*\(|WScript\.Shell|powershell|cmd\.exe)',
        'dynamic_code': r'(?i)(?:\beval\s*\(|ExecuteGlobal|\bExecute\b|\batob\s*\(|fromCharCode)',
    }
    found = [name for name, pattern in features.items() if re.search(pattern, decoded)]
    from .contexts import redact
    return {'source': source, 'sha256': hashlib.sha256(code.encode('utf-8', 'replace')).hexdigest(), 'characters': len(code), 'features': found, 'urls': list(dict.fromkeys(urls)), 'executed': False, 'code_excerpt':redact(code,1600)}


def pdf_actions(doc, limits) -> tuple[list[dict], list[str], list[str]]:
    actions, scripts, warnings = [], [], []
    started = time.monotonic()
    budget = _budget.get()
    cap = min(doc.xref_length(), 10000)
    if doc.xref_length() > cap:
        warnings.append('PDF active-object limit reached')
    for xref in range(1, cap):
        if time.monotonic() - started > min(3, max(0,12-(budget['seconds'] if budget else 0))):
            warnings.append('PDF active-object time budget reached')
            break
        try:
            keys = doc.xref_get_keys(xref)
            kind, value = doc.xref_get_key(xref, 'S')
            action = value.lstrip('/') if kind == 'name' else None
            if action in {'JavaScript', 'Launch', 'SubmitForm', 'GoToR', 'ImportData', 'Rendition'} or 'EmbeddedFiles' in keys or doc.xref_get_key(xref, 'Type') == ('name', '/EmbeddedFile'):
                item = {'xref': xref, 'type': action or 'EmbeddedFile', 'executed': False}
                for key in ('URI', 'F', 'Win/F'):
                    typ, target = doc.xref_get_key(xref, key)
                    if typ == 'string':
                        item['target_sha256'] = hashlib.sha256(target.encode()).hexdigest()
                        if target.lower().startswith(('https://', 'http://')):
                            item['url'] = normalize_url(target).redacted
                            # Preserve real URLs only inside extraction, never report text.
                            scripts.append(target)
                if action == 'JavaScript':
                    typ, js = doc.xref_get_key(xref, 'JS')
                    if typ == 'xref':
                        target_xref = int(js.split()[0])
                        raw = doc.xref_stream_raw(target_xref) or b''
                        filter_type, filter_value = doc.xref_get_key(target_xref, 'Filter')
                        if len(raw) > limits.max_xml_bytes:
                            warnings.append('PDF JavaScript compressed stream limit reached')
                            continue
                        if filter_type == 'null':
                            decoded = raw[:250001]
                        elif filter_value in {'/FlateDecode', '[/FlateDecode]'}:
                            decoded = zlib.decompressobj().decompress(raw, 250001)
                        else:
                            warnings.append('Unsupported PDF JavaScript stream filter')
                            decoded = b''
                        if len(decoded) > 250000:
                            warnings.append('PDF JavaScript decoded stream limit reached')
                        js = decoded[:250000].decode('utf-8', 'replace')
                    if typ in {'string', 'xref'} and js:
                        scripts.append(js[:250000])
                        item['script'] = script_facts(js[:250000], f'pdf:xref-{xref}')
                actions.append(item)
                if len(actions) >= 200:
                    warnings.append('PDF action limit reached')
                    break
        except Exception:
            # Bad references never turn a failed parse into a safe document.
            if 'PDF active-object parsing incomplete' not in warnings:
                warnings.append('PDF active-object parsing incomplete')
    if budget is not None:
        budget['seconds'] += time.monotonic()-started
    return actions, scripts, warnings


def _vba_facts(data: bytes, name: str) -> tuple[list[dict], list[str], list[str]]:
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return [], [], ['VBA parser unavailable; install antiphish-local[active]']
    observations, scripts, warnings = [], [], []
    parser = None
    try:
        parser = VBA_Parser(name, data=data, relaxed=False)
        if parser.detect_vba_macros():
            for index, (_, stream, module, code) in enumerate(parser.extract_macros()):
                if index >= 100:
                    warnings.append('VBA module limit reached'); break
                if isinstance(code, bytes):
                    code = code.decode('utf-8', 'replace')
                if len(code) > 250000:
                    warnings.append('VBA module text limit reached')
                code = code[:250000]
                observations.append(script_facts(code, 'vba:' + str(module)[:160]))
                scripts.append(code)
                if sum(map(len, scripts)) > 1000000:
                    warnings.append('VBA total code limit reached'); break
    except Exception as exc:
        warnings.append('VBA parsing incomplete: ' + type(exc).__name__)
    finally:
        if parser:
            parser.close()
    return observations, scripts, warnings


def vba_facts(data: bytes, name: str) -> tuple[list[dict], list[str], list[str]]:
    """Bound a third-party macro decompressor outside the API process."""
    import importlib.util
    import json
    import subprocess
    import sys
    import threading
    import os
    if importlib.util.find_spec('oletools') is None:
        return [], [], ['VBA parser unavailable; install antiphish-local[active]']
    budget = _budget.get()
    timeout = min(8, max(0, 12-(budget['seconds'] if budget else 0)))
    if timeout < .2:
        return [], [], ['Active-content total time budget reached']
    started = time.monotonic()
    process = subprocess.Popen([sys.executable, '-m', 'antiphish.vbaworker', name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    import psutil
    worker = psutil.Process(process.pid)
    finished = threading.Event()
    def monitor():
        while not finished.wait(.2):
            try:
                if process.poll() is not None:
                    return
                if worker.memory_info().rss > 512*1024*1024:
                    process.kill(); return
            except psutil.Error:
                return
    thread = threading.Thread(target=monitor, daemon=True); thread.start()
    try:
        output, _ = process.communicate(data, timeout=timeout)
        if process.returncode or len(output) > 4*1024*1024:
            return [], [], ['VBA parser resource limit or worker failure']
        payload = json.loads(output)
        return payload['observations'], payload['scripts'], payload['warnings']
    except (subprocess.TimeoutExpired, ValueError, KeyError):
        process.kill(); process.communicate()
        return [], [], ['VBA parser time limit or invalid worker response']
    finally:
        finished.set(); thread.join(timeout=1)
        if budget is not None:
            budget['seconds'] += time.monotonic()-started
