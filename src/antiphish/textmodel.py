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


def text_windows(text, tokenizer, *, max_tokens=384, max_windows=6):
    """Keep the beginning, end and distributed middle; bound adversarial inputs.

    The model was trained on short messages. Long emails must not silently lose
    their CTA, nor should arbitrary-length messages produce unlimited inference.
    """
    capacity = max_tokens - tokenizer.num_special_tokens_to_add(pair=False)
    # Character cap bounds tokenization too. Preserve both ends before tokenizing.
    bounded = text if len(text) <= 48000 else text[:24000] + '\n' + text[-24000:]
    ids = tokenizer(bounded, add_special_tokens=False, truncation=False)['input_ids']
    if len(ids) <= capacity:
        return [ids], [(0, len(ids))], len(ids), len(text)>48000
    stride = max(1, capacity - 96)
    starts = list(range(0, max(1, len(ids)-capacity+1), stride))
    if starts[-1] != len(ids)-capacity:
        starts.append(len(ids)-capacity)
    if max_windows<1:raise ValueError('At least one text window is required')
    if len(starts) > max_windows:
        starts = [starts[0]] if max_windows==1 else [starts[round(i*(len(starts)-1)/(max_windows-1))] for i in range(max_windows)]
    spans = [(s, min(len(ids), s+capacity)) for s in starts]
    covered = set(i for a,b in spans for i in range(a,b))
    return [ids[a:b] for a,b in spans], spans, len(ids), len(covered)<len(ids) or len(text)>48000


def score(text: str, path: Path = DEFAULT_PATH, *, head_only=False) -> dict:
    import torch
    started = time.perf_counter()
    tokenizer, model = _load(str(path))
    windows, spans, tokens, limited = text_windows(text, tokenizer, max_windows=6)
    if head_only:
        windows, spans = windows[:1], spans[:1]
    # Public batch API works with both Transformers 4 tokenizers and the v5
    # TokenizersBackend (which no longer exposes prepare_for_model).
    fragments = [text if i == 0 and len(text)<=48000 else tokenizer.decode(ids, skip_special_tokens=True, clean_up_tokenization_spaces=False) for i,ids in enumerate(windows)]
    results = []
    # Small batches avoid temporary eager-attention allocations on CPU/GPU.
    for offset in range(0, len(fragments), 2):
        inputs = tokenizer(fragments[offset:offset+2], padding=True, truncation=True, max_length=384, return_tensors='pt').to(model.device)
        with torch.inference_mode():
            results.append(torch.softmax(model(**inputs).logits.float(), dim=-1).cpu())
    values = torch.cat(results)
    if not torch.isfinite(values).all():
        raise ValueError('Non-finite classifier scores')
    labels = [model.config.id2label[i].lower() for i in range(values.shape[-1])]
    if not {'fraud', 'spam', 'legitimate'} <= set(labels):
        raise ValueError('Unexpected classifier label mapping')
    selected = int(values[:,labels.index('fraud')].argmax())
    scores = {label: round(float(value), 6) for label, value in zip(labels,values[selected])}
    if not {'fraud', 'spam', 'legitimate'} <= scores.keys():
        raise ValueError('Unexpected classifier label mapping')
    evidence = tokenizer.decode(windows[selected], skip_special_tokens=True)
    from .contexts import redact
    return {'model': REPOSITORY, 'revision': REVISION, 'scores': scores,
            'input_characters': len(text), 'input_tokens':tokens, 'max_tokens': 384,
            'windows':len(windows), 'coverage_limited':limited,
            'evidence_is_full_text':len(windows)==1 and not limited,
            'aggregation':'highest-fraud-window; not a calibrated document probability',
            'selected_window':selected, 'selected_token_span':list(spans[selected]),
            'evidence_text':redact(evidence,1800),
            'window_scores':[{label:round(float(v),6) for label,v in zip(labels,row)} for row in values],
            'suspicious': False, 'blocking': False, 'calibrated_on_russian_mail': False,
            'runtime_ms': round((time.perf_counter()-started)*1000,2)}


def configured_score(text: str, *, force=False):
    if not text.strip():
        return [{'model':REPOSITORY,'status':'NO_TEXT','note':'Нет извлечённого текста.','suspicious':False,'blocking':False}],[]
    value = os.environ.get('ANTIPHISH_TEXT_MODEL_DIR') or (str(DEFAULT_PATH) if force else None)
    if not value:
        return [], []
    try:
        return [score(text, Path(value))], []
    except Exception as exc:
        return [], ['Optional text classifier unavailable: ' + type(exc).__name__]

