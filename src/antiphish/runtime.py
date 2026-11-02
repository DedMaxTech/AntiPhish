"""Small reproducibility manifest, shared by reports, batches and benchmarks."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import os
import time
from pathlib import Path
from functools import lru_cache

from . import __version__
from .config import MODEL_DIR, RESOURCE_DIR, logo_index_path


def file_revision(path: Path) -> dict:
    if not path.is_file():
        return {"present": False}
    stat = path.stat()
    return {"present": True, "bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}


@lru_cache(maxsize=8)
def _catalog_digest(path: str, size: int, mtime: int) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def manifest(kb: Path) -> dict:
    catalog = RESOURCE_DIR / "brands.json"
    stat = catalog.stat()
    sources = sorted(Path(__file__).parent.glob('*.py'))
    source_revision = tuple((str(p), p.stat().st_size, p.stat().st_mtime_ns) for p in sources)
    llm = Path(os.environ.get('ANTIPHISH_LLM_MODEL_DIR', str(MODEL_DIR/'Qwen3.5-4B')))
    text = os.environ.get('ANTIPHISH_TEXT_MODEL_DIR') or str(MODEL_DIR/'phishing-scam-detector-base')
    return {
        "application_version": __version__, "python": platform.python_version(),
        "libraries": _libraries(),
        "decision_date": time.strftime('%Y-%m-%d'),
        "implementation_sha256": _implementation_digest(source_revision),
        "platform": platform.system(),
        "brands_sha256": _catalog_digest(str(catalog), stat.st_size, stat.st_mtime_ns),
        "link_wrappers": file_revision(RESOURCE_DIR/'link_wrappers.json'),
        "knowledge": file_revision(kb), "reputation": file_revision(kb.with_suffix('.reputation.sqlite')),
        "allowlist": file_revision(kb.with_suffix('.domains.sqlite')),
        "models": {name: file_revision(MODEL_DIR / name / "config.json") for name in ("Qwen3.5-4B", "siglip2-base-patch16-224")},
        "model_weight_files": {name: {p.name:file_revision(p) for p in (MODEL_DIR/name).glob('*.safetensors')} for name in ('Qwen3.5-4B','siglip2-base-patch16-224')},
        "llm_configuration": file_revision(llm/'config.json'),
        "text_classifier": {"enabled_by_environment": bool(os.environ.get('ANTIPHISH_TEXT_MODEL_DIR')), "configuration": file_revision(Path(text)/'config.json'),"weight_files":{p.name:file_revision(p) for p in Path(text).glob('*.safetensors')}},
        "laya": {"enabled_by_environment":bool(os.environ.get('ANTIPHISH_LAYA_MODEL_DIR')),
                 "weights":file_revision(Path(os.environ.get('ANTIPHISH_LAYA_MODEL_DIR',str(MODEL_DIR/'laya-multilingual'/'multilingual')))/'model.safetensors'),
                 "can_request_review":True,"can_confirm_phishing":False},
        "logo_index": file_revision(logo_index_path()),
        "visual_backend": {'kind':'local-pixel-shape-sift-ransac','gallery':file_revision(RESOURCE_DIR/'logo-gallery/manifest.jsonl'),
                           'operator_gallery':file_revision(MODEL_DIR/'logo-references'/'manifest.jsonl'),
                           'independent_accuracy_calibrated':False},
    }


@lru_cache(maxsize=4)
def _implementation_digest(revision) -> str:
    digest = hashlib.sha256()
    for path, _, _ in revision:
        digest.update(Path(path).name.encode())
        digest.update(Path(path).read_bytes())
    return digest.hexdigest()


@lru_cache(maxsize=1)
def _libraries() -> dict:
    versions = {}
    for name in ('certifi','lxml','Pillow','PyMuPDF','pypdf','opencv-python','playwright','tldextract','psutil','rapidocr','onnxruntime','torch','transformers','fastapi','oletools'):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def signature(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()

