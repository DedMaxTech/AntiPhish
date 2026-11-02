"""Explicit local labels. Benign labels never whitelist a domain or cancel proof."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .models import Evidence, Severity
from .texttools import normalize_russian
from .utils import simhash64

SCHEMA = '''CREATE TABLE IF NOT EXISTS reviewed_samples(
id TEXT PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
name TEXT NOT NULL, report_id TEXT NOT NULL, comment TEXT NOT NULL,
created_at TEXT NOT NULL, updated_at TEXT NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_reviewed_hash ON reviewed_samples(sha256);'''


def message_signature(text, subject='', brands=()):
    words = re.findall(r'[^\W\d_]{3,}', normalize_russian(text).casefold())[:6000]
    shingles = [' '.join(words[i:i+3]) for i in range(max(0, len(words)-2))]
    return {'text':simhash64(shingles), 'words':len(words),
        'subject':simhash64(re.findall(r'\w+', normalize_russian(subject).casefold())),
        'brands':sorted(set(brands))}


def save_review(kb_path: Path, stored: dict, learning: dict, label: str, comment: str, page_ids: list[str]) -> dict:
    if label not in {'phishing', 'benign'}:
        raise ValueError('Unknown label')
    report = stored['report']
    digest = report.get('input', {}).get('sha256')
    if not digest:
        # URL reviews are snapshots, not permanent URL/domain permissions.
        digest = hashlib.sha256(json.dumps([(p['sha256'],p.get('url')) for p in report.get('pages',[])],sort_keys=True).encode()).hexdigest() if report.get('pages') else None
    if not digest or report.get('analysis_status') == 'FAILED':
        raise ValueError('No successfully extracted sample to review')
    pages = {p['id']:p for p in learning.get('pages', [])}
    if not set(page_ids) <= set(pages):
        raise ValueError('Selected page is not part of the saved analysis')
    identifier = digest[:32]
    now = datetime.now(timezone.utc).isoformat()
    payload = {'page_ids':page_ids, 'message_signature':learning.get('message_signature'),
        'input_kind':report.get('input',{}).get('detected_type'), 'exact_input':bool(report.get('input',{}).get('sha256'))}
    Path(kb_path).parent.mkdir(parents=True, exist_ok=True)
    from .kb import initialize_empty_kb
    if not Path(kb_path).exists():
        initialize_empty_kb(kb_path)
    from .templates import SCHEMA as TEMPLATE_SCHEMA
    with closing(sqlite3.connect(kb_path,timeout=30)) as con, con:
        con.executescript(SCHEMA + TEMPLATE_SCHEMA)
        con.execute('DELETE FROM behavior_templates WHERE source_id LIKE ?', ('review:'+identifier+':%',))
        added=0
        for page_id in page_ids:
            page = pages[page_id]
            if not page.get('has_forms') or page.get('identity_source') != 'dom' or not page.get('dom'):
                continue
            con.execute('INSERT OR REPLACE INTO behavior_templates VALUES(?,?,?,?,?,?,?,?)',
                (page['sha256'],'review:'+identifier+':'+page_id,'',page['dom'],page['text'],page['types'],label,'user-reviewed-page'))
            added+=1
        con.execute('''INSERT INTO reviewed_samples VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(sha256) DO UPDATE SET label=excluded.label,name=excluded.name,
            report_id=excluded.report_id,comment=excluded.comment,updated_at=excluded.updated_at,payload=excluded.payload''',
            (identifier,digest,label,report.get('input',{}).get('name') or report.get('input',{}).get('value',''),stored['report_id'],comment[:2000],now,now,json.dumps(payload,ensure_ascii=False)))
    return {'id':identifier,'sha256':digest,'label':label,'selected_pages':added,'ignored_pages':len(page_ids)-added,
        'effect':'Exact confirmed sample and selected form templates' if label=='phishing' else 'Exact original-input soft heuristics and negative similarity; network/IOC/form proof remains active'}


def list_reviews(kb_path: Path, limit=100) -> list[dict]:
    if not Path(kb_path).exists():
        return []
    with closing(sqlite3.connect(Path(kb_path).resolve().as_uri()+'?mode=ro',uri=True)) as con:
        try:
            rows = con.execute('SELECT id,sha256,label,name,report_id,comment,created_at,updated_at,payload FROM reviewed_samples ORDER BY updated_at DESC LIMIT ?', (min(1000,max(1,limit)),)).fetchall()
        except sqlite3.OperationalError:
            return []
    keys = ('id','sha256','label','name','report_id','comment','created_at','updated_at','payload')
    return [{**dict(zip(keys,row)), 'payload':json.loads(row[-1])} for row in rows]


def delete_review(kb_path: Path, identifier: str) -> bool:
    if not re.fullmatch('[0-9a-f]{32}',identifier) or not Path(kb_path).exists():
        return False
    with closing(sqlite3.connect(kb_path,timeout=30)) as con, con:
        try:
            count = con.execute('DELETE FROM reviewed_samples WHERE id=?',(identifier,)).rowcount
            con.execute('DELETE FROM behavior_templates WHERE source_id LIKE ?',('review:'+identifier+':%',))
        except sqlite3.OperationalError:
            return False
    return bool(count)


def apply_reviewed_samples(report, extracted, kb_path: Path):
    if not Path(kb_path).exists():
        return
    with closing(sqlite3.connect(Path(kb_path).resolve().as_uri()+'?mode=ro',uri=True)) as con:
        try:
            exact = con.execute('SELECT id,label,comment,payload FROM reviewed_samples WHERE sha256=?',(report.input.get('sha256'),)).fetchone()
            candidates = con.execute('SELECT id,label,payload FROM reviewed_samples ORDER BY updated_at DESC LIMIT 2500').fetchall() if extracted.kind == 'eml' else []
        except sqlite3.OperationalError:
            return
    if exact and json.loads(exact[3]).get('exact_input'):
        identifier,label,comment,_ = exact
        report.review = {'id':identifier,'label':label,'match':'exact','comment':comment}
        if label == 'benign':
            soft = {'CAMPAIGN_TEMPLATE_MATCH','REVIEWED_MESSAGE_SIMILARITY','UNVERIFIED_REWARD_LURE',
                'UNVERIFIED_INVESTMENT_LURE','UNVERIFIED_ACCOUNT_LURE','UNVERIFIED_TRANSFER_LURE',
                'ACCOUNT_RECOVERY_ON_USER_HOSTING','DOCUMENT_IDENTITY_HOSTING_MISMATCH',
                'SECURITY_THREAT_TO_MESSENGER','REPLY_FOR_REWARD','CREDENTIAL_LURE',
                'MAILBOX_REVIEW_LURE','FAKE_DOCUMENT_VIEWER','VISUAL_REWARD_LURE'}
            original_scopes = extracted.metadata.get('message_scopes',{p.id for p in report.pages if not p.url})
            removed = [e for e in report.reason_codes if e.code in soft and (e.scope_id in original_scopes or e.scope_id in {None,'message'})]
            report.reason_codes[:] = [e for e in report.reason_codes if e not in removed]
            report.review['suppressed_reason_codes'] = sorted({e.code for e in removed})
        report.reason_codes.append(Evidence('REVIEWED_PHISHING_SAMPLE' if label=='phishing' else 'REVIEWED_BENIGN_SAMPLE',
            Severity.CRITICAL if label=='phishing' else Severity.INFO,
            'Точное совпадение с образцом, вручную подтверждённым как фишинговый' if label=='phishing' else 'Точное совпадение с легитимным образцом; независимые доказательства проверены отдельно',
            {'review_id':identifier,'sha256':report.input.get('sha256'),'comment':comment,'blocking':label=='phishing','suppressed_reason_codes':report.review.get('suppressed_reason_codes',[])},independent_group='manual-review'))
    if extracted.kind != 'eml' or exact:
        return
    brands = [b.brand for b in report.brands]
    current = message_signature(extracted.metadata.get('message_text',extracted.text), extracted.metadata.get('subject',''), brands)
    if current['words'] < 35 or not brands:
        return
    from .policy import catalog, official_host, effective_host
    identities = [b for b,_ in catalog() if b['name'] in brands]
    actions = [u for u in report.urls if u.source in {'html:a:href','text','link-wrapper'} and 'ACTION_URL' not in u.flags]
    if not any(not any(official_host(effective_host(u),b['domains']) for b in identities) for u in actions):
        return
    hits, negative = [], False
    for identifier,label,raw in candidates:
        known = json.loads(raw).get('message_signature')
        if not known or known['brands'] != current['brands'] or not .8 <= current['words']/max(1,known['words']) <= 1.25:
            continue
        distance = (int(current['text'],16)^int(known['text'],16)).bit_count()
        subject_distance = (int(current['subject'],16)^int(known['subject'],16)).bit_count()
        if distance <= 3 and subject_distance <= 4:
            negative |= label == 'benign'
            if label == 'phishing': hits.append({'review_id':identifier,'text_distance':distance,'subject_distance':subject_distance})
    if hits and not negative:
        report.reason_codes.append(Evidence('REVIEWED_MESSAGE_SIMILARITY',Severity.MEDIUM,
            'Текст и тема близки к проверенному фишинговому письму, действие ведёт вне доменов бренда',
            {'matches':hits[:3],'blocking':False},independent_group='manual-similarity',scope_id='message'))
