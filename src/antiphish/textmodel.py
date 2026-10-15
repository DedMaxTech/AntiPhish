"""Optional local multilingual classifier in observation mode, not blocking."""
from __future__ import annotations

import hashlib
import json
import os
import time
from functools import lru_cache
from pathlib import Path

from .config import MODEL_DIR

REPOSITORY = 'Horizon-Labs/phishing-scam-detector-base'
REVISION = 'f1dddff04e7f56dc9f0f068d4e7f0383c583e392'
DEFAULT_PATH = MODEL_DIR / 'phishing-scam-detector-base'


def setup(destination: Path = DEFAULT_PATH):
    from huggingface_hub import snapshot_download
    path = snapshot_download(REPOSITORY, revision=REVISION, local_dir=destination, allow_patterns=['*.json', '*.safetensors', '*.txt', 'README.md', 'LICENSE'])
    (Path(path)/'antiphish-source.json').write_text(json.dumps({'repository': REPOSITORY, 'revision': REVISION, 'license': 'Apache-2.0', 'mode': 'observation-only'}),encoding='utf-8')
    return {'path': str(path), 'repository': REPOSITORY, 'revision': REVISION, 'blocking': False}


@lru_cache(maxsize=1)
def _load(path: str):
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(path, local_files_only=True, trust_remote_code=False, use_safetensors=True, attn_implementation='eager')
    model.to('cuda' if torch.cuda.is_available() else 'cpu').eval()
    return tokenizer, model


def score(text: str, path: Path = DEFAULT_PATH) -> dict:
    import torch
    started = time.perf_counter()
    tokenizer, model = _load(str(path))
    inputs = tokenizer(text, return_tensors='pt', truncation=True, max_length=384).to(model.device)
    with torch.inference_mode():
        values = torch.softmax(model(**inputs).logits.float(), dim=-1)[0]
    if not torch.isfinite(values).all():
        raise ValueError('Non-finite classifier scores')
    scores = {model.config.id2label[i].lower(): round(float(value), 6) for i, value in enumerate(values.cpu())}
    if not {'fraud', 'spam', 'legitimate'} <= scores.keys():
        raise ValueError('Unexpected classifier label mapping')
    return {'model': REPOSITORY, 'revision': REVISION, 'scores': scores, 'input_characters': len(text), 'max_tokens': 384, 'suspicious': False, 'blocking': False, 'calibrated_on_russian_mail': False, 'runtime_ms': round((time.perf_counter()-started)*1000,2)}


def configured_score(text: str):
    value = os.environ.get('ANTIPHISH_TEXT_MODEL_DIR')
    if not value:
        return [], []
    try:
        return [score(text, Path(value))], []
    except Exception as exc:
        return [], ['Optional text classifier unavailable: ' + type(exc).__name__]

