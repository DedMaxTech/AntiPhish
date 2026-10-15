"""Download snapshots explicitly; analysis performs SQLite lookups only."""
from __future__ import annotations

import bz2
import hashlib
import json
import sqlite3
import time
import os
import urllib.error
import urllib.request
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from .urltools import ioc_url_key

SCHEMA = """
CREATE TABLE IF NOT EXISTS reputation_urls(
  url_hash TEXT NOT NULL, provider TEXT NOT NULL, url TEXT NOT NULL,
  confidence TEXT NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY(url_hash,provider));
CREATE TABLE IF NOT EXISTS reputation_sources(
  provider TEXT PRIMARY KEY, endpoint TEXT NOT NULL, updated_at INTEGER NOT NULL,
  records INTEGER NOT NULL, etag TEXT, sha256 TEXT NOT NULL, confidence TEXT NOT NULL);
"""


@dataclass(frozen=True)
class Feed:
    name: str
    endpoint: str
    format: str
    confidence: str
    terms: str


FEEDS = {
    "phishing-database": Feed("phishing-database", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt", "text", "community", "https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE"),
    "openphish": Feed("openphish", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", "text", "verified", "https://openphish.com/terms.html"),
    "phishtank": Feed("phishtank", "https://data.phishtank.com/data/online-valid.json.bz2", "phishtank-bz2", "verified", "https://phishtank.org/developer_info.php"),
}
MAX_DOWNLOAD = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
TTL_SECONDS = 7 * 86400


def parse_feed(feed: Feed, data: bytes) -> list[str]:
    if feed.format == "phishtank-bz2":
        decoder = bz2.BZ2Decompressor()
        expanded = decoder.decompress(data, max_length=MAX_EXPANDED + 1)
        if len(expanded) > MAX_EXPANDED or not decoder.eof:
            raise ValueError("Feed expansion exceeds limit or is incomplete")
        objects = json.loads(expanded)
        candidates = [row["url"] for row in objects if row.get("verified") == "yes" and row.get("online") == "yes"]
    else:
        text = data.decode("utf-8-sig", "strict")
        if "<html" in text[:2000].lower() or "<!doctype" in text[:2000].lower():
            raise ValueError("Feed returned an HTML error page")
        candidates = text.splitlines()
    urls = set()
    for raw in candidates:
        raw = raw.strip()
        if not raw or raw.startswith("#") or len(raw) > 8192:
            continue
        try:
            urls.add(ioc_url_key(raw))
        except (ValueError, UnicodeError):
            pass
    if len(urls) < 20:
        raise ValueError("Feed contains too few valid URLs; old snapshot retained")
    return sorted(urls)


def install_snapshot(path: Path, feed: Feed, urls: list[str], *, etag=None, digest="", now=None) -> dict:
    now = int(time.time()) if now is None else now
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, timeout=60)) as con, con:
        con.executescript(SCHEMA)
        previous = con.execute("SELECT records FROM reputation_sources WHERE provider=?", (feed.name,)).fetchone()
        if previous and len(urls) < previous[0] // 10:
            raise ValueError("Unexpected feed shrink; old snapshot retained")
        # One transaction replaces this provider only. Readers see either
        # snapshot; interruption or a failed feed cannot erase other providers.
        con.execute("DELETE FROM reputation_urls WHERE provider=?", (feed.name,))
        con.executemany("INSERT INTO reputation_urls VALUES(?,?,?,?,?)", ((hashlib.sha256(u.encode()).hexdigest(), feed.name, u, feed.confidence, now + TTL_SECONDS) for u in urls))
        con.execute("INSERT OR REPLACE INTO reputation_sources VALUES(?,?,?,?,?,?,?)", (feed.name, feed.endpoint, now, len(urls), etag, digest, feed.confidence))
    return {"provider": feed.name, "status": "UPDATED", "records": len(urls), "updated_at": now, "terms": feed.terms}


def update_feeds(path: Path, providers=None, progress=None) -> dict:
    results = []
    for name in providers or ("phishing-database", "openphish"):
        feed = FEEDS[name]
        if progress:
            progress(f"Downloading {name}")
        try:
            endpoint = feed.endpoint
            key = os.environ.get("ANTIPHISH_PHISHTANK_KEY") if name == "phishtank" else None
            if key:
                from urllib.parse import quote
                endpoint = endpoint.replace("/data/","/data/"+quote(key,safe="")+"/")
            request = urllib.request.Request(endpoint, headers={"User-Agent": "phishtank/AntiPhish-local-2.0 (noncommercial snapshot client)", "Accept-Encoding": "identity"})
            with urllib.request.urlopen(request, timeout=45) as response:
                blob = response.read(MAX_DOWNLOAD + 1)
                if len(blob) > MAX_DOWNLOAD:
                    raise ValueError("Feed download exceeds limit")
                etag = response.headers.get("ETag")
            urls = parse_feed(feed, blob)
            result = install_snapshot(path, feed, urls, etag=etag, digest=hashlib.sha256(blob).hexdigest())
            results.append(result)
            if progress:
                progress(f"Installed {name}: {len(urls)} URLs")
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            if key:
                error = error.replace(key,"[redacted]")
            results.append({"provider": name, "status": "FAILED", "error": error, "old_snapshot_preserved": True})
    return {"status": "OK" if all(r["status"] == "UPDATED" for r in results) else "PARTIAL", "sources": results, "local": True, "per_message_requests": 0}


def lookup(con: sqlite3.Connection, raw: str, now=None) -> list[dict]:
    now = int(time.time()) if now is None else now
    try:
        key = hashlib.sha256(ioc_url_key(raw).encode()).hexdigest()
        rows = con.execute("SELECT provider,confidence,expires_at FROM reputation_urls WHERE url_hash=? AND expires_at>?", (key, now)).fetchall()
    except sqlite3.OperationalError:
        return []
    return [dict(zip(("provider", "confidence", "expires_at"), row)) for row in rows]


def status(path: Path) -> dict:
    if not path.exists():
        return {"status": "EMPTY", "sources": []}
    try:
        with closing(sqlite3.connect(path.resolve().as_uri()+"?mode=ro", uri=True)) as con:
            rows = con.execute("SELECT provider,updated_at,records,confidence FROM reputation_sources").fetchall()
    except sqlite3.OperationalError:
        return {"status": "EMPTY", "sources": []}
    now = int(time.time())
    sources = [dict(zip(("provider", "updated_at", "records", "confidence"), row)) for row in rows]
    for source in sources:
        source["age_hours"] = round((now - source["updated_at"]) / 3600, 1)
        source["stale"] = now - source["updated_at"] >= TTL_SECONDS
    return {"status": "STALE" if sources and all(s["stale"] for s in sources) else "READY" if sources else "EMPTY", "sources": sources, "local_only": True}
