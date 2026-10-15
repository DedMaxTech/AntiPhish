"""Unverified domain context, deliberately incapable of bypassing detection."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import sqlite3
import tempfile
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import idna

from .urltools import _TLD_EXTRACTOR


def domain(value: str) -> tuple[str | None, str | None]:
    value = value.strip().lower().rstrip('.')
    if not value or any(c in value for c in ('/', ':', '*', '@', '?', '#', ' ')):
        return None, 'invalid-domain'
    try:
        value = idna.encode(value, uts46=True, std3_rules=True).decode()
    except idna.IDNAError:
        return None, 'invalid-idna'
    try:
        ipaddress.ip_address(value)
        return None, 'ip-address'
    except ValueError:
        pass
    if len(value) > 253 or '.' not in value:
        return None, 'invalid-domain'
    suffix = _TLD_EXTRACTOR(value) if _TLD_EXTRACTOR else None
    if not suffix or not suffix.suffix or not suffix.domain:
        return None, 'public-or-private-suffix'
    if value in {'example.com', 'example.net', 'example.org', 'localhost'} or value.endswith(('.invalid', '.test', '.localhost', '.example')):
        return None, 'reserved-example'
    return value, None


def import_domains(source: Path, destination: Path) -> dict:
    source, destination = Path(source), Path(destination)
    if source.stat().st_size > 20 * 1024 * 1024:
        raise ValueError('Domain CSV byte limit reached')
    counts, accepted = Counter(), set()
    with source.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or 'domain' not in reader.fieldnames:
            raise ValueError('CSV needs a domain column')
        for index, row in enumerate(reader):
            if index >= 200000:
                raise ValueError('Domain row limit reached')
            value, error = domain(row.get('domain', ''))
            if error:
                counts[error] += 1
            elif value in accepted:
                counts['duplicate'] += 1
            else:
                accepted.add(value)
    metadata = {'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'imported_at': datetime.now(timezone.utc).isoformat(), 'accepted': len(accepted), 'rejected': dict(counts), 'verified': False, 'purpose': 'exact-host context only; no SAFE verdict, no subdomain inheritance, no suppression of IOC/form checks'}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='domains-') as folder:
        staged = Path(folder) / 'domains.sqlite'
        with closing(sqlite3.connect(staged)) as con, con:
            con.executescript('CREATE TABLE domains(host TEXT PRIMARY KEY); CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);')
            con.executemany('INSERT INTO domains VALUES(?)', ((v,) for v in sorted(accepted)))
            con.execute('INSERT INTO metadata VALUES(?,?)', ('import', json.dumps(metadata)))
        os.replace(staged, destination)
    return metadata


def annotate(report, path: Path):
    if not path.is_file():
        return
    hosts = sorted({u.host for u in report.urls if u.host})
    matched = []
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as con:
        for start in range(0, len(hosts), 500):
            chunk = hosts[start:start + 500]
            matched.extend(x[0] for x in con.execute('SELECT host FROM domains WHERE host IN (' + ','.join('?' for _ in chunk) + ')', chunk))
    report.configuration['domain_context'] = {'matched_exact_hosts': matched, 'verified': False, 'affects_verdict': False, 'subdomains_inherited': False}
