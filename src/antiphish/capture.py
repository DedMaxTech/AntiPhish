"""Current link checks and local page captures using the analyzer's transport."""
from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .config import DEFAULT_LIMITS
from .network import safe_http_get
from .urltools import normalize_url
from .utils import atomic_json


def inspect_url(value: str, *, output_dir: Path | None = None) -> dict:
    row = {'checked_at': datetime.now(timezone.utc).isoformat()}
    try:
        url = normalize_url(value)
        row.update(url=url.redacted, host=url.host, id=hashlib.sha256(url.normalized.encode()).hexdigest())
        if 'TOKENIZED_URL' in url.flags or re.search(r'(?i)(?:@|%40)', url.normalized) or url.host in {'example.com', 'example.net', 'example.org'} or url.host.endswith(('.example', '.invalid', '.test')):
            row['status'] = 'SKIPPED_PRIVATE_OR_PLACEHOLDER'
            return row
        fetched = safe_http_get(url.normalized, replace(DEFAULT_LIMITS, network_timeout_seconds=8, max_http_bytes=3*1024*1024))
        row.update(status='FETCHED', final_url=normalize_url(fetched.final_url).redacted, http_status=fetched.status, content_type=fetched.content_type, bytes=len(fetched.body), sha256=hashlib.sha256(fetched.body).hexdigest(), redirects=fetched.chain)
        if 'html' in fetched.content_type:
            text = fetched.body.decode(fetched.charset or 'utf-8', 'replace')
            title = re.search(r'(?is)<title[^>]*>(.*?)</title>', text)
            row['title'] = re.sub('<[^>]+>', '', title.group(1)).strip()[:240] if title else ''
            row['likely_error_or_gate'] = bool(re.search(r'(?i)(?:404|not found|access denied|just a moment|captcha|page removed|сайт недоступен|страница не найдена)', row['title']))
            if output_dir:
                try:
                    folder = Path(output_dir) / row['id']; folder.mkdir(parents=True, exist_ok=True)
                    (folder/'page.html').write_bytes(fetched.body)
                    # Kept locally for faithful relative-link resolution. Never
                    # publish this capture folder without reviewing its contents.
                    atomic_json(folder/'origin.json', {'url': fetched.final_url, 'charset': fetched.charset, 'checked_at': row['checked_at'], 'sha256': row['sha256'], 'label': None, 'review_status': 'needs_review'})
                    row.update(capture=str(folder/'page.html'), capture_status='SAVED')
                except OSError as exc:
                    # A disk/storage failure is not evidence that HTTP failed.
                    row.update(capture_status='FAILED', capture_error=type(exc).__name__)
    except Exception as exc:
        row.update(status='UNAVAILABLE', error=type(exc).__name__)
    return row


def check_urls(urls: list[str], *, output_dir: Path | None = None, max_urls=100) -> dict:
    values = list(dict.fromkeys(urls))
    selected = values[:max_urls]
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda value: inspect_url(value, output_dir=output_dir), selected))
    from collections import Counter
    return {'checked_at': datetime.now(timezone.utc).isoformat(), 'total_unique_urls': len(values), 'checked': len(rows), 'limited': len(values) > len(selected), 'statuses': dict(Counter(r['status'] for r in rows)), 'rows': rows,
            'note': 'HTTP availability and title are observations only. A working URL is not a verified phishing/benign label. Captures require independent review before quality metrics.'}

