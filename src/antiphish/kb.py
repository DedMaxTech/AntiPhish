from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
import time
import zipfile
import tempfile
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import ARTIFACT_DIR, DEFAULT_KB, DEFAULT_LIMITS, RESOURCE_DIR
from .extractors import extract_html, extract_image
from .utils import atomic_json


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS known_hashes(
  sha256 TEXT PRIMARY KEY, object_type TEXT NOT NULL, verdict TEXT NOT NULL,
  source TEXT NOT NULL, first_seen TEXT, expires_at TEXT, provenance TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS url_iocs(
  value TEXT PRIMARY KEY, value_type TEXT NOT NULL, verdict TEXT NOT NULL,
  source TEXT NOT NULL, expires_at TEXT
);
CREATE TABLE IF NOT EXISTS fingerprints(
  id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, sha256 TEXT NOT NULL,
  dom_sha256 TEXT, dom_simhash64 TEXT, features_json TEXT NOT NULL, label TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fingerprints_sha ON fingerprints(sha256);
CREATE TABLE IF NOT EXISTS brands(
  name TEXT PRIMARY KEY, aliases_json TEXT NOT NULL, domains_json TEXT NOT NULL,
  active INTEGER NOT NULL, provenance TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_stats(
  source TEXT PRIMARY KEY, stats_json TEXT NOT NULL, built_at TEXT NOT NULL
);
"""


@dataclass(slots=True)
class BuildStats:
    html_files: int = 0
    png_files: int = 0
    other_files: int = 0
    html_bytes: int = 0
    png_bytes: int = 0
    long_path_png: int = 0
    target_brand_entries: int = 0
    target_brand_files: int = 0
    target_brand_names: int = 0
    target_brand_raw_names: int = 0
    unique_sha256: int = 0
    duplicate_objects: int = 0
    fingerprint_records: int = 0
    fingerprint_extraction_errors: int = 0


class KnowledgeBase:
    def __init__(self, path: Path = DEFAULT_KB):
        self.path = path

    @property
    def reputation_path(self) -> Path:
        separate = self.path.with_suffix(".reputation.sqlite")
        return separate if separate.exists() else self.path

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path.resolve().as_uri()+"?mode=ro", uri=True)
        con.execute("PRAGMA query_only=ON")
        return con

    def lookup_hash(self, digest: str) -> dict | None:
        if not self.path.exists():
            return None
        con = self.connect()
        try:
            row = con.execute(
                "SELECT sha256,object_type,verdict,source,expires_at,provenance FROM known_hashes WHERE sha256=? AND (expires_at IS NULL OR expires_at>=?) AND object_type NOT IN ('png','image','screenshot')",
                (digest, time.strftime("%Y-%m-%d")),
            ).fetchone()
        finally:
            con.close()
        if not row:
            return None
        return dict(zip(("sha256", "object_type", "verdict", "source", "expires_at", "provenance"), row))

    def lookup_url(self, host: str, normalized: str) -> dict | None:
        if not self.path.exists():
            return None
        today = time.strftime("%Y-%m-%d")
        con = self.connect()
        try:
            row = con.execute(
                "SELECT value,value_type,source,expires_at FROM url_iocs WHERE ((value=? AND value_type='url') OR (value=? AND value_type='host')) AND verdict='PHISHING' AND (expires_at IS NULL OR expires_at>=?)",
                (normalized, host, today),
            ).fetchone()
        finally:
            con.close()
        return dict(zip(("value", "value_type", "source", "expires_at"), row)) if row else None

    def reputation_matches(self, urls) -> list[tuple]:
        if not self.path.exists():
            return []
        from .reputation import lookup
        from contextlib import closing
        with closing(sqlite3.connect(self.reputation_path.resolve().as_uri()+"?mode=ro",uri=True)) as con:
            return [(item, matches) for item in urls if item.host and (matches := lookup(con, item.navigation_url or item.normalized))]


def _find_zip(case_dir: Path, stem: str) -> Path:
    candidates = list(case_dir.glob(f"{stem}.zip")) + list(case_dir.rglob(f"{stem}.zip"))
    if not candidates:
        raise FileNotFoundError(f"{stem}.zip not found below {case_dir}")
    return candidates[0]


def build_case_kb(case_dir: Path, output: Path = DEFAULT_KB, progress=None) -> dict:
    """Build in a staging DB. Preserve feeds/manual IOC and the old DB on error."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kb-build-", dir=output.parent) as directory:
        staged = Path(directory) / "knowledge.sqlite"
        if output.exists():
            with closing(sqlite3.connect(output)) as original, closing(sqlite3.connect(staged)) as target:
                original.backup(target)
            with closing(sqlite3.connect(staged)) as target, target:
                target.execute("DELETE FROM fingerprints WHERE sha256 IN (SELECT sha256 FROM known_hashes WHERE source='case-2-html_phishing.zip')")
                target.execute("DELETE FROM known_hashes WHERE source='case-2-html_phishing.zip'")
        result = _build_case_kb(case_dir, staged, progress, preserve=True)
        with closing(sqlite3.connect(staged)) as target:
            target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            target.execute("PRAGMA journal_mode=DELETE")
        staged.replace(output)
        for name in ("fingerprints.jsonl", "sha256-manifest.csv", "case-build-report.json"):
            (Path(directory) / name).replace(output.parent / name)
    result["knowledge_base"] = output.name
    export_runtime_artifacts(output)
    return result


def _build_case_kb(case_dir: Path, output: Path, progress=None, preserve=False) -> dict:
    case_dir = case_dir.resolve()
    html_zip = _find_zip(case_dir, "html_phishing")
    brand_zip = _find_zip(case_dir, "target_brands")
    output.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    if output.exists() and not preserve:
        output.unlink()
    con = sqlite3.connect(output)
    con.executescript(SCHEMA)
    stats = BuildStats()
    built_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with (RESOURCE_DIR / "brands.json").open(encoding="utf-8") as fh:
        brand_payload = json.load(fh)
    for brand in brand_payload["brands"]:
        con.execute(
            "INSERT OR REPLACE INTO brands VALUES(?,?,?,?,?)",
            (brand["name"], json.dumps(brand["aliases"], ensure_ascii=False), json.dumps(brand["domains"], ensure_ascii=False), int(brand["active"]), brand["provenance"]),
        )

    with zipfile.ZipFile(brand_zip) as archive:
        infos = archive.infolist()
        stats.target_brand_entries = len(infos)
        stats.target_brand_files = sum(not i.is_dir() for i in infos)
        # The archive has brand names as its first path component.
        names = set()
        for info in infos:
            parts = Path(info.filename.replace("\\", "/")).parts
            if parts:
                names.add(parts[0])
        stats.target_brand_raw_names = len(names)
        # Windows treats META and Meta as the same directory; normalize like
        # the intended extraction target so the usable brand count is 175.
        stats.target_brand_names = len({name.casefold().rstrip(" .") for name in names})
        for name in sorted(names, key=str.casefold):
            canonical = name.rstrip(" .")
            con.execute(
                "INSERT OR IGNORE INTO brands VALUES(?,?,?,?,?)",
                (canonical, json.dumps([canonical], ensure_ascii=False), "[]", 0, "case-2-empty-directory-name-unverified"),
            )

    fingerprint_path = output.parent / "fingerprints.jsonl"
    manifest_path = output.parent / "sha256-manifest.csv"
    with zipfile.ZipFile(html_zip) as archive, fingerprint_path.open("w", encoding="utf-8", newline="\n") as fp, manifest_path.open("w", encoding="utf-8", newline="") as mf:
        writer = csv.writer(mf)
        writer.writerow(["sha256", "type", "source_id", "label"])
        infos = [i for i in archive.infolist() if not i.is_dir()]
        for index, info in enumerate(infos, 1):
            suffix = Path(info.filename).suffix.lower()
            if suffix not in {".html", ".htm", ".png"}:
                stats.other_files += 1
                continue
            data = archive.read(info)
            digest = hashlib.sha256(data).hexdigest()
            object_type = "html" if suffix in {".html", ".htm"} else "png"
            if object_type == "html":
                stats.html_files += 1
                stats.html_bytes += len(data)
            else:
                stats.png_files += 1
                stats.png_bytes += len(data)
                if len(str((case_dir / "html_phishing" / info.filename).resolve())) >= 260:
                    stats.long_path_png += 1
            con.execute(
                "INSERT OR REPLACE INTO known_hashes VALUES(?,?,?,?,?,?,?)",
                (digest, object_type, "PHISHING", "case-2-html_phishing.zip", None, None, "provider-labelled-phishing-sample"),
            )
            try:
                parsed = extract_html(data, DEFAULT_LIMITS) if object_type == "html" else extract_image(data, DEFAULT_LIMITS)
                features = parsed.fingerprints
            except Exception as exc:
                # A malformed sample must not abort the complete archive index.
                # The error type is retained for audit without serialising raw data.
                features = {"sha256": digest, "fingerprint_error": type(exc).__name__}
                stats.fingerprint_extraction_errors += 1
            con.execute(
                "INSERT INTO fingerprints(source_id,sha256,dom_sha256,dom_simhash64,features_json,label) VALUES(?,?,?,?,?,?)",
                (
                    info.filename,
                    digest,
                    features.get("dom_sha256"),
                    features.get("dom_simhash64"),
                    json.dumps(features, ensure_ascii=False, sort_keys=True),
                    "phishing",
                ),
            )
            stats.fingerprint_records += 1
            record = {
                "source_id": info.filename,
                "sha256": digest,
                "object_type": object_type,
                "label": "phishing",
                "fingerprints": features,
            }
            fp.write(json.dumps(record, ensure_ascii=False) + "\n")
            writer.writerow([digest, object_type, info.filename, "phishing"])
            if progress and index % 500 == 0:
                progress(index, len(infos))
        con.execute(
            "INSERT OR REPLACE INTO source_stats VALUES(?,?,?)",
            (html_zip.name, json.dumps(asdict(stats), ensure_ascii=False), built_at),
        )
    stats.unique_sha256 = con.execute("SELECT count(*) FROM known_hashes WHERE source='case-2-html_phishing.zip'").fetchone()[0]
    stats.duplicate_objects = stats.html_files + stats.png_files - stats.unique_sha256
    con.execute(
        "INSERT OR REPLACE INTO source_stats VALUES(?,?,?)",
        (html_zip.name, json.dumps(asdict(stats), ensure_ascii=False), built_at),
    )
    con.execute("INSERT OR REPLACE INTO metadata VALUES('schema_version','1.0')")
    con.execute("INSERT OR REPLACE INTO metadata VALUES('built_at',?)", (built_at,))
    con.commit()
    con.close()
    report = {
        "status": "OK",
        "case_dir": case_dir.name,
        "html_zip": html_zip.name,
        "brand_zip": brand_zip.name,
        "brand_zip_diagnosis": "DAMAGED_OR_EMPTY_PAYLOAD" if stats.target_brand_entries and stats.target_brand_files == 0 else "HAS_FILES",
        "stats": asdict(stats),
        "knowledge_base": output.name,
        "built_at": built_at,
    }
    atomic_json(output.parent / "case-build-report.json", report)
    return report


def initialize_empty_kb(output: Path = DEFAULT_KB) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(output)
    try:
        con.executescript(SCHEMA)
        payload = json.loads((RESOURCE_DIR / "brands.json").read_text(encoding="utf-8"))
        for brand in payload["brands"]:
            con.execute("INSERT OR REPLACE INTO brands VALUES(?,?,?,?,?)", (brand["name"], json.dumps(brand["aliases"], ensure_ascii=False), json.dumps(brand["domains"], ensure_ascii=False), int(brand["active"]), brand["provenance"]))
        con.execute("INSERT OR REPLACE INTO metadata VALUES('schema_version','1.0')")
        con.commit()
    finally:
        con.close()


def export_runtime_artifacts(kb_path: Path = DEFAULT_KB) -> None:
    artifact_dir = kb_path.parent
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if kb_path.exists():
        payload = json.loads((RESOURCE_DIR / "brands.json").read_text(encoding="utf-8"))
        with closing(sqlite3.connect(kb_path)) as con, con:
            for brand in payload["brands"]:
                con.execute(
                    "INSERT OR REPLACE INTO brands VALUES(?,?,?,?,?)",
                    (
                        brand["name"],
                        json.dumps(brand["aliases"], ensure_ascii=False),
                        json.dumps(brand["domains"], ensure_ascii=False),
                        int(brand["active"]),
                        brand["provenance"],
                    ),
                )
    (artifact_dir / "rules.json").write_text((RESOURCE_DIR / "rules.json").read_text(encoding="utf-8"), encoding="utf-8")
    (artifact_dir / "brands.json").write_text((RESOURCE_DIR / "brands.json").read_text(encoding="utf-8"), encoding="utf-8")
    _export_brand_vectors(artifact_dir / "brands.npz")
    (artifact_dir / "iocs.txt").write_text("# type,value,expires_at,source\n", encoding="utf-8")
    (artifact_dir / "antiphish.yar").write_text(
        'rule AntiPhish_Confirmed_Samples {\n  meta:\n    description = "Use SHA-256 manifest for exact matches; no broad content rules emitted"\n  condition:\n    false\n}\n',
        encoding="utf-8",
    )
    if not (artifact_dir / "fingerprints.jsonl").exists():
        (artifact_dir / "fingerprints.jsonl").write_text("", encoding="utf-8")
    if not (artifact_dir / "sha256-manifest.csv").exists():
        (artifact_dir / "sha256-manifest.csv").write_text("sha256,type,source_id,label\n", encoding="utf-8")


def _export_brand_vectors(path: Path) -> None:
    """Deterministic compact lexical vectors; visual model scores stay auxiliary."""
    import numpy as np
    payload = json.loads((RESOURCE_DIR / "brands.json").read_text(encoding="utf-8"))
    names = []
    vectors = []
    for brand in payload["brands"]:
        if not brand.get("active"):
            continue
        vector = np.zeros(256, dtype=np.float32)
        terms = [brand["name"], *brand.get("aliases", [])]
        for term in terms:
            padded = f"  {term.casefold()}  "
            for i in range(max(0, len(padded) - 2)):
                token = padded[i:i+3].encode("utf-8")
                bucket = int.from_bytes(hashlib.blake2b(token, digest_size=2).digest(), "big") % 256
                vector[bucket] += 1
        norm = float(np.linalg.norm(vector))
        if norm:
            vector /= norm
        names.append(brand["name"])
        vectors.append(vector)
    np.savez_compressed(path, names=np.asarray(names), vectors=np.stack(vectors), kind="lexical-char3-v1")
