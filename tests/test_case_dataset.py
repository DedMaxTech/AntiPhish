from __future__ import annotations

import os
import zipfile
from pathlib import Path, PurePosixPath

import pytest


CASE_DIR = Path(os.environ.get("ANTIPHISH_CASE_DIR", r"C:\Users\Max\Downloads\Кейс_2\Кейс_2"))


@pytest.mark.integration
def test_original_archives_are_complete_as_observed():
    html_zip = CASE_DIR / "html_phishing.zip"
    brand_zip = CASE_DIR / "target_brands.zip"
    if not html_zip.exists() or not brand_zip.exists():
        pytest.skip("Case archives are not available")
    with zipfile.ZipFile(html_zip) as archive:
        files = [i for i in archive.infolist() if not i.is_dir()]
        assert sum(PurePosixPath(i.filename).suffix.lower() in {".html", ".htm"} for i in files) == 7642
        pngs = [i for i in files if PurePosixPath(i.filename).suffix.lower() == ".png"]
        assert len(pngs) == 2854
        assert sum(len(str((CASE_DIR / "html_phishing" / i.filename).resolve())) >= 260 for i in pngs) == 86
    with zipfile.ZipFile(brand_zip) as archive:
        infos = archive.infolist()
        assert len(infos) == 1489
        assert sum(not i.is_dir() for i in infos) == 0
        raw_names = {PurePosixPath(i.filename).parts[0] for i in infos}
        assert len({name.casefold().rstrip(" .") for name in raw_names}) == 175
