"""Similarity provides supporting evidence; never converts an asset hash to a block."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path

from .models import Evidence, Severity
from .utils import simhash64

SCHEMA = """CREATE TABLE IF NOT EXISTS behavior_templates(
sha256 TEXT NOT NULL, source_id TEXT NOT NULL, brand TEXT NOT NULL,
dom_simhash TEXT, text_simhash TEXT, sensitive_types TEXT NOT NULL,
label TEXT NOT NULL, provenance TEXT NOT NULL, PRIMARY KEY(sha256,source_id));
CREATE INDEX IF NOT EXISTS idx_behavior_types ON behavior_templates(sensitive_types);
"""


def signature(page, fingerprints):
    words = re.findall(r"[^\W\d_]{3,}", page.text.casefold(), re.UNICODE)
    shingles = [" ".join(words[i:i+3]) for i in range(max(0,len(words)-2))]
    types = sorted({t for f in page.forms for t in f.sensitive_types})
    return fingerprints.get("dom_simhash64"), simhash64(shingles), json.dumps(types)


def import_corpus(path: Path, kb_path: Path, progress=None):
    from .corpus import read_corpus
    from .extractors import extract_html
    from .config import DEFAULT_LIMITS
    records, mails = 0, 0
    with closing(sqlite3.connect(kb_path)) as con, con:
        con.executescript(SCHEMA)
        for sample in read_corpus(path):
            mails += 1
            from .policy import catalog
            canonical_brand = next((b["name"] for b,patterns in catalog() if any(p.search(sample.brand.casefold()) for p in patterns)),sample.brand)
            for key, capture in sample.pages.items():
                parsed = extract_html(capture.body, DEFAULT_LIMITS, capture.final_url)
                for page in parsed.pages:
                    dom, text, types = signature(page, parsed.fingerprints)
                    con.execute("INSERT OR REPLACE INTO behavior_templates VALUES(?,?,?,?,?,?,?,?)", (page.sha256, path.name+":"+sample.id+":"+hashlib.sha256(key.encode()).hexdigest()[:12], canonical_brand, dom, text, types, "provider-phishing-unreviewed", "recorded-page; may include legitimate landing or error pages"))
                    records += 1
            if progress and mails % 50 == 0:
                progress(mails)
    return {"emails":mails,"templates":records,"exact_blocking_hashes_added":0,"labels":"unreviewed; similarity is review evidence only"}


def learn_file(path: Path, kb_path: Path, label: str, source: str):
    from .config import DEFAULT_LIMITS
    from .extractors import extract_html
    parsed = extract_html(path.read_bytes(), DEFAULT_LIMITS)
    with closing(sqlite3.connect(kb_path)) as con, con:
        con.executescript(SCHEMA)
        for page in parsed.pages:
            dom, text, types = signature(page, parsed.fingerprints)
            con.execute("INSERT OR REPLACE INTO behavior_templates VALUES(?,?,?,?,?,?,?,?)", (page.sha256, source, "", dom, text, types, label, "user-labelled-example"))
    return {"templates":len(parsed.pages),"label":label}


def match_pages(report, kb_path: Path):
    if not kb_path.exists():
        return
    with closing(sqlite3.connect(kb_path.resolve().as_uri()+"?mode=ro",uri=True)) as con:
        for page in report.pages:
            if not page.forms:
                continue
            from .policy import catalog, credential_host
            brands = [b for b, _ in catalog() if b["name"] in page.claimed_brands]
            # A corpus can contain official sign-in pages. A learned visual
            # clone must not turn the real issuer into a suspicious campaign.
            if brands and all(any(credential_host(page.host, b, f.sensitive_types) and credential_host(f.destination_host, b, f.sensitive_types) for b in brands) for f in page.forms):
                continue
            fp = report.fingerprints
            for item in fp.get("network_pages",[]):
                if item.get("url") == page.url:
                    fp = item["fingerprints"]
                    break
            dom, text, types = signature(page, fp)
            if not dom or not text:
                continue
            try:
                candidates = con.execute("SELECT source_id,brand,dom_simhash,text_simhash,label FROM behavior_templates WHERE sensitive_types=? AND dom_simhash IS NOT NULL",(types,)).fetchall()
            except sqlite3.OperationalError:
                return
            hits, benign = [], False
            for source, brand, d, t, label in candidates:
                distance_dom = (int(dom,16)^int(d,16)).bit_count()
                distance_text = (int(text,16)^int(t,16)).bit_count()
                if distance_dom > 3 or distance_text > 4:
                    continue
                if label == "benign":
                    benign = True
                elif label == "phishing" or brand in page.claimed_brands:
                    hits.append({"source":source,"brand":brand,"dom_distance":distance_dom,"text_distance":distance_text,"label":label})
            if hits and not benign:
                report.reason_codes.append(Evidence("CAMPAIGN_TEMPLATE_MATCH",Severity.MEDIUM,"Форма и текст близки к образцу фишинговой кампании",{"matches":hits[:3],"blocking":False},independent_group="similarity",scope_id=page.id))
