from __future__ import annotations

import collections
import tarfile
import tempfile
import time
from pathlib import Path

from .analyzer import Analyzer
from .benchmark import clopper_pearson_zero_upper
from .config import REPORT_DIR
from .utils import atomic_json


def run_spamassassin_ham_benchmark(archives: list[Path], progress=None) -> dict:
    """Evaluate all regular messages from official easy/hard-ham archives."""
    analyzer = Analyzer(Path(tempfile.gettempdir()) / "antiphish-deliberately-missing-kb.sqlite")
    verdicts: collections.Counter[str] = collections.Counter()
    statuses: collections.Counter[str] = collections.Counter()
    flagged: list[dict] = []
    total = 0
    started = time.perf_counter()
    per_archive = {}
    for archive_path in archives:
        archive_total = 0
        with tarfile.open(archive_path, "r:*") as archive:
            members = [m for m in archive.getmembers() if m.isfile() and not Path(m.name).name.startswith("cmds")]
            for member in members:
                fileobj = archive.extractfile(member)
                if fileobj is None:
                    continue
                report = analyzer.analyze(fileobj.read(), name=Path(member.name).name + ".eml", network="offline")
                verdicts[report.verdict.value] += 1
                statuses[report.analysis_status.value] += 1
                total += 1
                archive_total += 1
                if report.verdict.value != "NOT_DETECTED":
                    flagged.append({"archive": archive_path.name, "source_id": member.name, "verdict": report.verdict.value, "reason_codes": [e.code for e in report.reason_codes], "analysis_status": report.analysis_status.value})
                if progress and total % 250 == 0:
                    progress(total)
        per_archive[archive_path.name] = archive_total
    block_fp = verdicts["PHISHING"]
    review_fp = verdicts["SUSPICIOUS"]
    result = {
        "benchmark": "spamassassin-easy-hard-ham",
        "evidence_scope": "full regular-message contents of the supplied official ham archives",
        "archives": per_archive,
        "samples": total,
        "verdicts": dict(verdicts),
        "analysis_statuses": dict(statuses),
        "metrics": {
            "observed_block_fpr": block_fp / total if total else None,
            "block_fpr_per_million": block_fp / total * 1_000_000 if total else None,
            "observed_review_rate": review_fp / total if total else None,
            "zero_block_fp_95pct_upper_bound": clopper_pearson_zero_upper(total) if total and block_fp == 0 else None,
        },
        "all_flagged": flagged,
        "duration_seconds": round(time.perf_counter() - started, 2),
    }
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    atomic_json(REPORT_DIR / "spamassassin-ham-benchmark.json", result)
    return result

