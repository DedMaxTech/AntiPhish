"""Documentation benchmark, 2026-10-07. Does not alter detector decisions/data."""
from __future__ import annotations

import collections
import importlib.metadata
import json
import math
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from antiphish.analyzer import Analyzer
from antiphish.config import DEFAULT_KB, DEFAULT_LIMITS
from antiphish.corpus import read_corpus, replay_fetch
from antiphish.network import FetchResult
from antiphish.reputation import status

WORK = Path(__file__).parent
RESULT = WORK / "performance_results.json"
ARCHIVE = Path(r"C:\Users\Max\Downloads\target_brands (1).zip")
REPO = Path(r"D:\Projects\Python\AntiPhish")


def russian(sample):
    return bool(re.search(r"[А-Яа-яЁё]", sample.brand)) or sample.brand.casefold() in {"wildberries", "ozon", "mailru", "moc ру", "dsl.su", "drweb", "pony express"}


def percentile(values, q):
    values = sorted(values)
    index = (len(values)-1)*q
    lo, hi = math.floor(index), math.ceil(index)
    return values[lo] + (values[hi]-values[lo])*(index-lo)


def summary(rows, elapsed):
    values = [r["seconds"] for r in rows]
    return {"analyses": len(rows), "elapsed_seconds": round(elapsed, 4), "mean_seconds": round(sum(values)/len(values), 6), "median_seconds": round(percentile(values,.5),6), "p95_seconds": round(percentile(values,.95),6), "min_seconds": round(min(values),6), "max_seconds": round(max(values),6), "emails_per_minute": round(60*len(rows)/elapsed,2), "emails_per_hour": round(3600*len(rows)/elapsed,1), "verdicts": dict(collections.Counter(r["verdict"] for r in rows)), "statuses": dict(collections.Counter(r["status"] for r in rows)), "network_statuses": dict(collections.Counter(r["network_status"] for r in rows)), "model_parse_statuses": dict(collections.Counter(v for r in rows for v in r["model_parse"])), "model_warnings": sum(r["model_warnings"] for r in rows)}


def run(analyzer, data, *, profile, network="offline", fetcher=None):
    start = time.perf_counter()
    report = analyzer.analyze(data, name="benchmark.eml", profile=profile, network=network, browser_confirmation="I_UNDERSTAND" if network=="browser" else None, fetcher=fetcher)
    seconds = time.perf_counter()-start
    return {"seconds": seconds, "verdict": report.verdict.value, "status": report.analysis_status.value, "network_status": report.configuration.get("network_analysis_status"), "pages": len(report.pages), "urls": len(report.urls), "model_parse": [m.get("parse_status","VISUAL") for m in report.model_evidence], "model_names": [m["model"] for m in report.model_evidence], "model_warnings": len(report.model_warnings), "model_runtime_ms": [m["runtime_ms"] for m in report.model_evidence]}


def mail_with_link(url):
    message = EmailMessage()
    message["From"] = "Бухгалтерия <accounting@example.org>"
    message["Subject"] = "Документ по договору"
    message.set_content(f"<h1>Документ по договору</h1><p>Сведения для ознакомления, реквизиты прежние.</p><a href='{url}'>Открыть документ</a>", subtype="html", charset="utf-8")
    return message.as_bytes()


def save():
    RESULT.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")


samples = [s for s in read_corpus(ARCHIVE) if russian(s)]
assert len(samples)==42
packages = ["antiphish-local","idna","lxml","Pillow","PyMuPDF","pypdf","opencv-python","tldextract","playwright","rapidocr","onnxruntime","torch","transformers","accelerate","safetensors","numpy"]
result = {"date": datetime.now(timezone(timedelta(hours=7))).date().isoformat(), "time_zone": "Asia/Novosibirsk", "python": sys.version, "platform": platform.platform(), "cpu": "Intel Core i5-12600KF 10 cores 16 threads", "ram_gib": 63.9, "gpu": "NVIDIA GeForce RTX 4080 16 GB", "packages": {p:importlib.metadata.version(p) for p in packages}, "reputation":status(DEFAULT_KB.with_suffix('.reputation.sqlite')), "dataset": {"archive":ARCHIVE.name,"russian_emails":42,"available_pages":sum(len(s.pages) for s in samples),"min_bytes":min(len(s.mail) for s in samples),"median_bytes":percentile([len(s.mail) for s in samples],.5),"max_bytes":max(len(s.mail) for s in samples),"ids":[s.id for s in samples]}, "method": "Sequential API analyses in a persistent process; ZIP loading excluded; installed KB/feeds enabled. Hourly/minute figures are scaled estimates from batch elapsed time, not hour-long runs. No parallelism. CPU/OS/file caches are not flushed.", "groups":{}}
resume = '--resume' in sys.argv
if resume:
    result = json.loads(RESULT.read_text(encoding='utf-8'))
    old = result['groups'].pop('quality-browser-public', None)
    if old:
        result['exploratory_browser_default'] = old
result['method'] += ' Public HTTP/browser comparison limits traversal to one fetched page. Default traversal diagnostic is excluded from successful-capacity figures.'
analyzer = Analyzer()
# Parser/catalog warm-up is outside batch timings. No model is loaded yet.
run(analyzer, mail_with_link('https://example.com/'), profile='fast')
for profile in ('fast','quality'):
    if resume:
        continue
    rows=[]
    started=time.perf_counter()
    for repetition in range(3):
        for sample in samples:
            row=run(analyzer,sample.mail,profile=profile)
            row.update(id=sample.id,brand=sample.brand,repetition=repetition+1)
            rows.append(row)
    result['groups'][profile+'-offline-real']={"summary":summary(rows,time.perf_counter()-started),"rows":rows,"repeats":3,"unique_emails":42}
    save()
    print(profile,'offline',result['groups'][profile+'-offline-real']['summary'],flush=True)

# Actual HTTPS latency and real Edge startup/render/OCR on a harmless public page.
network_mail=mail_with_link('https://example.com/')
for network in ('offline','http','browser'):
    if resume and network == 'offline':
        continue
    public_analyzer = Analyzer(limits=replace(DEFAULT_LIMITS,max_network_pages=1))
    rows=[]
    started=time.perf_counter()
    for index in range(8):
        row=run(public_analyzer,network_mail,profile='quality',network=network)
        if network != 'offline':
            assert row['pages'] >= 2, row
        row['repetition']=index+1
        rows.append(row)
    result['groups']['quality-'+network+'-public']={"summary":summary(rows,time.perf_counter()-started),"rows":rows,"target":"https://example.com/","unique_emails":1,"repeats":8,"fixture":"Synthetic ordinary Russian mail, one link to public example.com; real HTTPS; no malicious targets"}
    result['groups']['quality-'+network+'-public']['max_network_pages'] = 1
    save()
    print('public',network,result['groups']['quality-'+network+'-public']['summary'],flush=True)

if not resume:
    rows=[]
    started=time.perf_counter()
    for sample in samples:
        rows.append({**run(analyzer,sample.mail,profile='quality',network='http',fetcher=replay_fetch(sample.pages)),"id":sample.id,"brand":sample.brand})
    result['groups']['quality-replay-real']={"summary":summary(rows,time.perf_counter()-started),"rows":rows,"fixture":"Recorded pages only; transport substituted, real internet latency excluded"}
    save()
    print('recorded routes complete',flush=True)

# Isolate rendering/probing overhead from internet latency using a controlled kit.
fixture_url='https://auth-benchmark.example/login'
fixture_body="""<title>СберБанк</title><h1>СберБанк</h1><form onsubmit='event.preventDefault()'><input type=email id=mail><button type=button onclick="document.getElementById('second').hidden=false;this.hidden=true">Далее</button><div id=second hidden><input type=password id=pw><button type=button onclick="fetch('/collect',{method:'POST',body:document.getElementById('pw').value})">Войти</button></div></form>""".encode()
transport_calls=[]
def fixture_fetch(raw,limits):
    transport_calls.append(raw)
    if raw != fixture_url:
        raise AssertionError('Unexpected synthetic transport request')
    return FetchResult(fixture_body,raw,[raw],'text/html','200',charset='utf-8')
fixture_mail=mail_with_link(fixture_url)
rows=[]
with patch('antiphish.network.is_public_host',return_value=(True,['93.184.216.34'])), patch('antiphish.network.safe_http_get',side_effect=fixture_fetch):
    started=time.perf_counter()
    for index in range(6):
        row=run(analyzer,fixture_mail,profile='quality',network='browser')
        assert row['verdict']=='PHISHING'
        rows.append(row)
    elapsed=time.perf_counter()-started
assert transport_calls==[fixture_url]*6
result['groups']['quality-browser-dynamic']={"summary":summary(rows,elapsed),"rows":rows,"fixture":"Controlled email then password form; real Edge/OCR/probing; transport substituted; no request with canary transmitted"}
save()
print('dynamic browser complete',flush=True)

# Separate one-shot CLI cost from a long-lived API worker. Run before parent GPU load.
with tempfile.TemporaryDirectory(prefix='antiphish-perf-',dir=WORK) as directory:
    source=Path(directory)/'benchmark.eml'
    source.write_bytes(samples[0].mail)
    env=dict(os.environ,PYTHONIOENCODING='utf-8',HF_HUB_DISABLE_PROGRESS_BARS='1')
    started=time.perf_counter()
    child=subprocess.run([sys.executable,'-m','antiphish','analyze',str(source),'--profile','deep','--network','offline','--json'],cwd=REPO,env=env,capture_output=True,text=True,encoding='utf-8',timeout=240)
    elapsed=time.perf_counter()-started
    payload=json.loads(child.stdout)
    result['cold_cli_deep']={"wall_seconds":round(elapsed,4),"reported_analysis_seconds":payload['timings_ms']['total']/1000,"exit_code":child.returncode,"status":payload['analysis_status'],"models":[m['model'] for m in payload['model_evidence']],"model_parse":[m.get('parse_status') for m in payload['model_evidence']],"model_warnings":payload['model_warnings'],"sample_id":samples[0].id,"description":"Fresh Python process and first model load; filesystem cache not flushed. Includes Python/module startup."}
save()
print('cold CLI deep',result['cold_cli_deep'],flush=True)

rows=[]
started=time.perf_counter()
for index,sample in enumerate(samples):
    row=run(analyzer,sample.mail,profile='deep')
    row.update(id=sample.id,brand=sample.brand)
    rows.append(row)
    assert 'Qwen3.5-4B-local' in row['model_names'], row
    result['groups']['deep-offline-real']={"summary":summary(rows,time.perf_counter()-started),"rows":rows,"unique_emails":len(rows),"repeats":1,"first_model_load_seconds":rows[0]['seconds'],"warm_summary":summary(rows[1:],sum(r['seconds'] for r in rows[1:])) if len(rows)>1 else None}
    save()
    print('deep',index+1,'/42',round(row['seconds'],2),'s',row['model_parse'],flush=True)

# Deep + browser invokes BOTH Qwen and SigLIP, unlike ordinary offline EML.
rows=[]
started=time.perf_counter()
for index in range(3):
    row=run(public_analyzer,network_mail,profile='deep',network='browser')
    assert 'SigLIP2-local-zero-shot' in row['model_names'], row
    rows.append(row)
result['groups']['deep-browser-public']={"summary":summary(rows,time.perf_counter()-started),"rows":rows,"fixture":"Same benign public-page mail; actual HTTPS/browser screenshot/OCR/Qwen/SigLIP. First SigLIP load included."}
import torch
result['gpu_peak_allocated_mb']=round(torch.cuda.max_memory_allocated()/1024**2,1)
result['complete']=True
save()
print('ALL BENCHMARKS COMPLETE',flush=True)
