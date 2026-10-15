from __future__ import annotations

import collections
import json
import tempfile
import time
import zipfile
from pathlib import Path

from .analyzer import Analyzer
from .config import REPORT_DIR
from .kb import _find_zip
from .utils import atomic_json


def run_case_behavior_benchmark(case_dir: Path, max_items: int | None = None, progress=None) -> dict:
    """Evaluate general rules with an empty KB: exact case hashes cannot help."""
    archive_path = _find_zip(case_dir.resolve(), "html_phishing")
    with tempfile.TemporaryDirectory(prefix="antiphish-eval-") as temp:
        kb_path = Path(temp) / "empty.sqlite"
        # Deliberately do not create the file: every KB lookup becomes a
        # guaranteed miss and cannot leak case knowledge into the benchmark.
        analyzer = Analyzer(kb_path)
        verdicts: collections.Counter[str] = collections.Counter()
        reasons: collections.Counter[str] = collections.Counter()
        families: collections.Counter[str] = collections.Counter()
        misses: list[dict] = []
        errors: list[dict] = []
        started = time.perf_counter()
        with zipfile.ZipFile(archive_path) as archive:
            infos = [i for i in archive.infolist() if not i.is_dir() and Path(i.filename).suffix.lower() in {".html", ".htm"}]
            if max_items is not None:
                infos = infos[:max_items]
            for index, info in enumerate(infos, 1):
                report = analyzer.analyze(archive.read(info), name=info.filename, network="offline")
                verdicts[report.verdict.value] += 1
                reasons.update({item.code for item in report.reason_codes})
                family = report.fingerprints.get("dom_simhash64") or "none"
                families[family] += 1
                if report.verdict.value == "NOT_DETECTED":
                    misses.append({"source_id": info.filename, "sha256": report.input.get("sha256"), "analysis_status": report.analysis_status.value, "reason_codes": [e.code for e in report.reason_codes]})
                if report.analysis_status.value == "FAILED":
                    errors.append({"source_id": info.filename, "warnings": report.warnings})
                if progress and (index % 100 == 0 or index == len(infos)):
                    progress(index, len(infos))
        total = sum(verdicts.values())
        detected = verdicts["PHISHING"] + verdicts["SUSPICIOUS"]
        report = {
            "benchmark": "case-2-behavioral-no-kb",
            "evidence_scope": "all selected provider-labelled HTML; exact hashes and case fingerprints disabled; captured error/legitimate pages may be present",
            "split_policy": "No fitting is performed. Every SHA-256 and DOM fingerprint is unseen by the empty evaluation KB; DOM families are reported for audit.",
            "source": archive_path.name,
            "samples": total,
            "verdicts": dict(verdicts),
            "metrics": {"provider_label_alert_rate": detected / total if total else None, "provider_label_block_rate": verdicts["PHISHING"] / total if total else None},
            "metric_note": "These are alert proportions over unreviewed provider labels, not verified recall or held-out effectiveness.",
            "families": {"unique_dom_simhash64": len(families), "largest_family": max(families.values(), default=0)},
            "reason_counts": dict(reasons.most_common()),
            "misses": misses,
            "errors": errors,
            "duration_seconds": round(time.perf_counter() - started, 2),
        }
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    atomic_json(REPORT_DIR / "case-behavior-benchmark.json", report)
    return report
