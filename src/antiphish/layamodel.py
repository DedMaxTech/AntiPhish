"""Optional local typed-decision model. Scores are observations, never a block."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import threading
import time
from functools import lru_cache
from pathlib import Path

from .config import MODEL_DIR

REPOSITORY='convaiinnovations/laya'
REVISION='7b928d828b7b0e022f929d9bd2e44165aa270148'
WEIGHT_SHA256='9d628fd971b700382ac6f65920a86f149777b2e748e0c955fb3b19695aa8f204'
DEFAULT_PATH=MODEL_DIR/'laya-multilingual'/'multilingual'
CATEGORIES={'phishing':'A deceptive or fraudulent message intended to steal credentials, secret data or money.',
            'benign':'Legitimate ordinary correspondence or a genuine notification.',
            'marketing':'Ordinary advertising or a legitimate marketing promotion.'}
QUESTIONS=[('category','choice',
    'Classify the email by its actual content. A deceptive request to steal credentials, secrets or money is phishing even if presented as a promotion. Ordinary advertising alone is not phishing.',
    [k+': '+v for k,v in CATEGORIES.items()]),
    ('fraud','noul','The email is a phishing attempt or a scam intended to steal credentials, secret data or money.',
    ['false: The message does not demonstrate such fraud.','true: The message demonstrates such fraud.'])]
_lock=threading.Lock()


def model_path():
    return Path(os.environ.get('ANTIPHISH_LAYA_MODEL_DIR',str(DEFAULT_PATH)))


def status():
    path=model_path()
    present=all((path/name).is_file() for name in ('model.safetensors','rl_agent_config.json','encoder/config.json','tokenizer/tokenizer.json'))
    runtime=all(importlib.util.find_spec(name) is not None for name in ('torch','transformers','safetensors'))
    return {'ready':present and runtime,'weights_present':present,'runtime_installed':runtime,
            'repository':REPOSITORY,'revision':REVISION,'directory':str(path),'local_only':True}


def setup():
    from huggingface_hub import snapshot_download
    path=Path(snapshot_download(REPOSITORY,revision=REVISION,allow_patterns=['multilingual/*','LICENSE*'],local_dir=DEFAULT_PATH.parent))/'multilingual'
    if hashlib.sha256((path/'model.safetensors').read_bytes()).hexdigest()!=WEIGHT_SHA256:
        raise ValueError('Laya weight checksum mismatch')
    return {'status':'READY','directory':str(path),'repository':REPOSITORY,'revision':REVISION}


@lru_cache(maxsize=1)
def _load(path):
    import torch
    from safetensors.torch import load_file
    from transformers import AutoConfig,AutoModel,AutoTokenizer
    from .laya_core import DecisionModel
    directory=Path(path)
    weight_digest=hashlib.sha256((directory/'model.safetensors').read_bytes()).hexdigest()
    cfg=json.loads((directory/'rl_agent_config.json').read_text(encoding='utf-8'))
    if cfg.get('head_layers')!=2:raise ValueError('Unsupported Laya architecture')
    tokenizer=AutoTokenizer.from_pretrained(directory/'tokenizer',local_files_only=True,trust_remote_code=False)
    encoder=AutoModel.from_config(AutoConfig.from_pretrained(directory/'encoder',local_files_only=True,trust_remote_code=False),attn_implementation='sdpa')
    model=DecisionModel(encoder)
    model.load_state_dict(load_file(directory/'model.safetensors'),strict=True)
    device='cuda' if torch.cuda.is_available() else 'cpu'
    model.to(device).eval()
    model.encoder.config.reference_compile=False
    cfg['loaded_weight_sha256']=weight_digest
    return tokenizer,model,cfg


def score(text,path=None,*,max_windows=3):
    import torch
    from .laya_core import sequence
    from .textmodel import text_windows
    from .contexts import redact
    started=time.perf_counter()
    with _lock,torch.inference_mode():
        tokenizer,model,cfg=_load(str(path or model_path()))
        room=min(sequence(tokenizer,'',ins,opts,kind)[2] for _,kind,ins,opts in QUESTIONS)
        # text_windows accounts for two special tokens. Both typed heads must
        # retain the complete selected fragment within their own context budget.
        windows,spans,tokens,limited=text_windows(text,tokenizer,max_tokens=room+2,max_windows=max_windows)
        fragments=[text if len(windows)==1 and len(text)<=48000 else tokenizer.decode(w,skip_special_tokens=True) for w in windows]
        rows=[]
        for fragment in fragments:
            built=[sequence(tokenizer,fragment,ins,opts,kind) for _,kind,ins,opts in QUESTIONS]
            width=max(len(item[0]) for item in built);nopt=max(len(item[1]) for item in built)
            ids=torch.full((len(built),width),tokenizer.pad_token_id,dtype=torch.long)
            mask=torch.zeros_like(ids);markers=torch.zeros((len(built),nopt),dtype=torch.long)
            marker_mask=torch.zeros_like(markers,dtype=torch.bool)
            for i,(seq,positions,_) in enumerate(built):
                ids[i,:len(seq)]=torch.tensor(seq);mask[i,:len(seq)]=1
                markers[i,:len(positions)]=torch.tensor(positions);marker_mask[i,:len(positions)]=True
            device=next(model.parameters()).device
            dtype=torch.bfloat16 if device.type=='cuda' and torch.cuda.is_bf16_supported() else torch.float16
            with torch.autocast(device_type=device.type,dtype=dtype,enabled=device.type=='cuda'):
                logits=model(ids.to(device),mask.to(device),markers.to(device),marker_mask.to(device),torch.tensor([0,2],device=device))
            values=[]
            for i,(_,kind,_,opts) in enumerate(QUESTIONS):
                qt=0 if kind=='choice' else 2;k=len(opts)
                bucket=('choice' if qt==0 else 'noul')+(':2' if k==2 else ':3-5')
                temp=cfg.get('temperature_by_options',{}).get(bucket,cfg.get('temperature',[1,1,1])[qt])
                values.append(torch.softmax(logits[i,:k].float()/temp,dim=-1).cpu().tolist())
            if any(not math.isfinite(v) for group in values for v in group):raise ValueError('Non-finite model scores')
            rows.append({'scores':dict(zip(CATEGORIES,values[0])),'fraud_score':values[1][1]})
    selected=max(range(len(rows)),key=lambda i:rows[i]['fraud_score'])
    chosen=rows[selected];top=max(chosen['scores'],key=chosen['scores'].get)
    assessment='phishing' if chosen['scores']['phishing']>=.9 and chosen['fraud_score']>=.9 else top if top!='phishing' and chosen['scores'][top]>=.9 and chosen['fraud_score']<.5 else 'uncertain'
    return {'model':'Laya multilingual','repository':REPOSITORY,'revision':REVISION if cfg['loaded_weight_sha256']==WEIGHT_SHA256 else 'custom-unverified',
            'weight_sha256':cfg['loaded_weight_sha256'],'status':'COMPLETE',
            'assessment':assessment,'scores':{k:round(v,6) for k,v in chosen['scores'].items()},
            'fraud_score':round(chosen['fraud_score'],6),'windows':len(rows),'window_scores':rows,
            'input_tokens':tokens,'max_tokens':1024,'coverage_limited':limited,
            'input_characters':len(text),'evidence_is_full_text':len(windows)==1 and not limited,
            'selected_window':selected,'selected_token_span':list(spans[selected]),
            'evidence_text':redact(tokenizer.decode(windows[selected],skip_special_tokens=True),2200),
            'aggregation':'highest-fraud-window; not a calibrated document probability',
            'role':'advisory','affects_verdict':False,'suspicious':False,'blocking':False,
            'runtime_ms':round((time.perf_counter()-started)*1000,2)}


def configured_score(text):
    if not text.strip():
        return [{'model':'Laya multilingual','status':'NO_TEXT','assessment':'unavailable','affects_verdict':False,
                 'note':'Нет извлечённого текста. Для изображения включите OCR.','suspicious':False,'blocking':False}],['Laya: нет текста для оценки']
    if not status()['ready']:
        return [{'model':'Laya multilingual','status':'UNAVAILABLE','assessment':'unavailable','affects_verdict':False,
                 'note':'Выполните antiphish setup-laya после установки зависимостей deep.','suspicious':False,'blocking':False}],['Laya: локальные веса или runtime не установлены']
    try:return [score(text)],[]
    except Exception as exc:
        return [{'model':'Laya multilingual','status':'FAILED','assessment':'unavailable','affects_verdict':False,
                 'note':type(exc).__name__,'suspicious':False,'blocking':False}],['Laya: '+type(exc).__name__]
