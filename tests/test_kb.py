from __future__ import annotations

import sqlite3
import zipfile
from io import BytesIO

from PIL import Image

import antiphish.kb as kb_module
from antiphish.kb import KnowledgeBase, SCHEMA


def test_lookup_releases_sqlite_file_on_windows(tmp_path):
    path = tmp_path / "kb.sqlite"
    con = sqlite3.connect(path)
    try:
        con.executescript(SCHEMA)
        con.commit()
    finally:
        con.close()
    kb = KnowledgeBase(path)
    assert kb.lookup_hash("0" * 64) is None
    assert kb.lookup_url("example.test", "https://example.test/") is None
    path.unlink()
    assert not path.exists()


def test_case_builder_persists_html_and_image_fingerprints(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    with zipfile.ZipFile(case_dir / "target_brands.zip", "w") as archive:
        archive.writestr("ExampleBrand/", b"")
    image_buffer = BytesIO()
    Image.new("RGB", (32, 32), "white").save(image_buffer, format="PNG")
    with zipfile.ZipFile(case_dir / "html_phishing.zip", "w") as archive:
        archive.writestr("sample.html", b"<html><body><form><input type='password'></form></body></html>")
        archive.writestr("sample.png", image_buffer.getvalue())

    monkeypatch.setattr(kb_module, "ARTIFACT_DIR", tmp_path / "artifacts")
    output = tmp_path / "knowledge.sqlite"
    report = kb_module.build_case_kb(case_dir, output)

    assert report["stats"]["fingerprint_records"] == 2
    assert report["stats"]["fingerprint_extraction_errors"] == 0
    with sqlite3.connect(output) as con:
        rows = con.execute("SELECT object_type,features_json FROM known_hashes JOIN fingerprints USING(sha256) ORDER BY object_type").fetchall()
    assert len(rows) == 2
    assert '"dom_sha256"' in rows[0][1]
    assert '"image_phash"' in rows[1][1]
