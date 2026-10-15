"""Optional local Cyrillic OCR; downloads happen only in setup-ocr."""
from __future__ import annotations

import hashlib
import importlib.util
import threading
import time
import urllib.request
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path

from .config import MODEL_DIR

OCR_DIR = MODEL_DIR / "ocr"
_BASE = "https://www.modelscope.cn/models/RapidAI/RapidOCR/resolve/v3.9.2/onnx/PP-OCRv5/"
MODELS = {
    "det": ("det/ch_PP-OCRv5_det_mobile.onnx", "4d97c44a20d30a81aad087d6a396b08f786c4635742afc391f6621f5c6ae78ae"),
    "rec": ("rec/cyrillic_PP-OCRv5_rec_mobile.onnx", "90f761b4bfcce0c8c561c0cb5c887b0971d3ec01c32164bdf7374a35b0982711"),
    "cls": ("cls/ch_PP-LCNet_x0_25_textline_ori_cls_mobile.onnx", "54379ae5174d026780215fc748a7f31910dee36818e63d49e17dc598ecc82df7"),
}
_budget = ContextVar("antiphish_ocr_budget", default=None)
_lock = threading.Lock()


def reset_budget():
    _budget.set({"count": 0, "seconds": 0.0})


def status():
    present = {key: (OCR_DIR / Path(relative).name).is_file() for key, (relative, _) in MODELS.items()}
    installed = importlib.util.find_spec("rapidocr") is not None
    return {"ready": installed and all(present.values()), "runtime_installed": installed, "models": present, "directory": str(OCR_DIR), "languages": "Cyrillic including Russian, plus Latin", "runtime_network": False}


def setup_models(progress=None):
    OCR_DIR.mkdir(parents=True, exist_ok=True)
    result = {}
    for key, (relative, digest) in MODELS.items():
        path = OCR_DIR / Path(relative).name
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == digest:
            result[key] = "PRESENT"
            continue
        if progress:
            progress("Downloading OCR " + key)
        temporary = path.with_suffix(".download")
        try:
            request = urllib.request.Request(_BASE + relative, headers={"User-Agent": "AntiPhish/2.0 model-setup"})
            sha, size = hashlib.sha256(), 0
            with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
                while chunk := response.read(65536):
                    size += len(chunk)
                    if size > 64 * 1024 * 1024:
                        raise ValueError("OCR model exceeds download limit")
                    sha.update(chunk)
                    output.write(chunk)
            if sha.hexdigest() != digest:
                raise ValueError("OCR model SHA256 mismatch")
            temporary.replace(path)
            result[key] = "INSTALLED"
        finally:
            temporary.unlink(missing_ok=True)
    _engine.cache_clear()
    return {"status": "READY" if status()["ready"] else "RUNTIME_MISSING", "models": result, "directory": str(OCR_DIR)}


@lru_cache(maxsize=1)
def _engine():
    from rapidocr import RapidOCR
    from rapidocr.utils.typings import LangRec, ModelType, OCRVersion
    paths = {key: OCR_DIR / Path(relative).name for key, (relative, _) in MODELS.items()}
    if not all(path.is_file() for path in paths.values()):
        raise FileNotFoundError("Run antiphish setup-ocr first")
    return RapidOCR(params={
        "Global.log_level": "error", "Global.max_side_len": 1800, "Global.text_score": .65,
        "EngineConfig.onnxruntime.intra_op_num_threads": 4,
        "EngineConfig.onnxruntime.inter_op_num_threads": 1,
        "EngineConfig.onnxruntime.use_cuda": False,
        "Det.ocr_version": OCRVersion.PPOCRV5, "Det.model_type": ModelType.MOBILE, "Det.model_path": str(paths["det"]),
        "Cls.model_path": str(paths["cls"]), "Cls.ocr_version": OCRVersion.PPOCRV5,
        "Rec.ocr_version": OCRVersion.PPOCRV5, "Rec.lang_type": LangRec.CYRILLIC, "Rec.model_type": ModelType.MOBILE, "Rec.model_path": str(paths["rec"]),
    })


def recognize(image):
    """Return text/status without downloading absent models implicitly."""
    if image.width < 120 or image.height < 40:
        return "", "TOO_SMALL"
    budget = _budget.get()
    if budget is None:
        reset_budget()
        budget = _budget.get()
    if budget["count"] >= 6 or budget["seconds"] >= 12:
        return "", "LIMITED"
    if not status()["ready"]:
        return "", "UNAVAILABLE"
    import numpy as np
    image = image.copy()
    image.thumbnail((1800, 1800))
    started = time.monotonic()
    budget["count"] += 1
    try:
        with _lock:
            result = _engine()(np.asarray(image.convert("RGB"))[:, :, ::-1], use_cls=True)
        texts = getattr(result, "txts", None)
        scores = getattr(result, "scores", None)
        if texts is None:
            return "", "COMPLETE"
        return "\n".join(text for text, score in zip(texts, scores) if score >= .65)[:12000], "COMPLETE"
    except Exception as exc:
        return "", "FAILED:" + type(exc).__name__
    finally:
        budget["seconds"] += time.monotonic() - started
