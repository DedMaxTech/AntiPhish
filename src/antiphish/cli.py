from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import sqlite3
import sys
from pathlib import Path

from .analyzer import Analyzer, EXIT_CODES
from .benchmark import run_builtin_benchmark
from .config import ARTIFACT_DIR, DEFAULT_KB, PROJECT_ROOT
from .gui import run_gui
from .kb import build_case_kb, export_runtime_artifacts, initialize_empty_kb
from .evaluation import run_case_behavior_benchmark
from .external_eval import run_spamassassin_ham_benchmark


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="antiphish", description="Локальный precision-first анализатор фишинга")
    root.add_argument("--version", action="version", version="AntiPhish 1.0.0")
    sub = root.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="проанализировать файл, URL или stdin")
    analyze.add_argument("source", help="путь, URL или -")
    analyze.add_argument("--profile", choices=("fast", "quality", "deep"), default="quality")
    analyze.add_argument("--network", choices=("offline", "http", "browser"), default="offline")
    analyze.add_argument("--confirm-browser-risk")
    analyze.add_argument("--json", action="store_true")
    analyze.add_argument("--output", type=Path)
    analyze.add_argument("--kb", type=Path, default=DEFAULT_KB)
    gui = sub.add_parser("gui", help="открыть демонстрационный GUI")
    build = sub.add_parser("build-kb", help="построить KB напрямую из ZIP кейса")
    build.add_argument("--case-dir", required=True, type=Path)
    build.add_argument("--output", type=Path, default=DEFAULT_KB)
    benchmark = sub.add_parser("benchmark", help="запустить встроенную или case-wide регрессионную проверку")
    benchmark.add_argument("--case-dir", type=Path, help="дополнительно проверить HTML кейса с пустой KB")
    benchmark.add_argument("--max-items", type=int, help="ограничить число HTML только для быстрого smoke-run")
    benchmark.add_argument("--spamassassin-ham", type=Path, action="append", default=[], help="официальный easy/hard ham .tar.bz2; можно повторить")
    sub.add_parser("doctor", help="проверить окружение")
    return root


def _print_human(report) -> None:
    print(f"Вердикт: {report.verdict.value}")
    print(f"Полнота: {report.analysis_status.value}")
    if report.reason_codes:
        print("Причины:")
        for item in report.reason_codes:
            print(f"  - {item.code}: {item.summary}")
    else:
        print("Причины: достаточных признаков не найдено")
    if report.warnings:
        print("Ограничения анализа:")
        for warning in report.warnings:
            print(f"  - {warning}")
    if report.network_warnings:
        print(f"Сетевое дополнение: {report.configuration.get('network_analysis_status')}")
        for warning in report.network_warnings:
            print(f"  - {warning}")
    if report.model_warnings:
        print("Локальные модели:")
        for warning in report.model_warnings:
            print(f"  - {warning}")
    print(f"URL: {len(report.urls)}; вложения: {len(report.attachments)}; время: {report.timings_ms.get('total')} мс")
    if report.verdict.value == "NOT_DETECTED":
        print("NOT_DETECTED означает отсутствие достаточных доказательств, а не гарантию легитимности.")


def doctor() -> dict:
    modules = ["lxml", "PIL", "fitz", "cv2", "playwright", "idna"]
    checks = {name: importlib.util.find_spec(name) is not None for name in modules}
    edge = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
    kb_ok = False
    kb_rows = 0
    if DEFAULT_KB.exists():
        try:
            with sqlite3.connect(DEFAULT_KB) as con:
                kb_rows = con.execute("SELECT count(*) FROM known_hashes").fetchone()[0]
                kb_ok = True
        except sqlite3.Error:
            pass
    deep = {"qwen_installed": (PROJECT_ROOT / "models" / "Qwen3.5-4B").is_dir(), "siglip2_installed": (PROJECT_ROOT / "models" / "siglip2-base-patch16-224").is_dir(), "torch": None, "cuda_available": False, "cuda_device": None}
    if importlib.util.find_spec("torch"):
        try:
            import torch
            deep.update(torch=torch.__version__, cuda_available=torch.cuda.is_available(), cuda_device=torch.cuda.get_device_name(0) if torch.cuda.is_available() else None)
        except Exception as exc:
            deep["error"] = f"{type(exc).__name__}: {exc}"
    return {"status": "OK" if all(checks.values()) else "DEGRADED", "python": sys.version, "platform": platform.platform(), "project_root": str(PROJECT_ROOT), "modules": checks, "edge": {"path": str(edge), "available": edge.exists()}, "knowledge_base": {"path": str(DEFAULT_KB), "valid": kb_ok, "known_hashes": kb_rows}, "deep": deep, "privacy": "runtime does not persist raw inputs"}


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "analyze":
        if not args.kb.exists():
            initialize_empty_kb(args.kb)
            export_runtime_artifacts(args.kb)
        source = sys.stdin.buffer.read() if args.source == "-" else args.source
        name = "stdin.html" if isinstance(source, bytes) and b"<html" in source[:500].lower() else "stdin.eml"
        report = Analyzer(args.kb).analyze(source, name=name, profile=args.profile, network=args.network, browser_confirmation=args.confirm_browser_risk)
        payload = report.to_dict()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            _print_human(report)
        return 30 if report.analysis_status.value == "FAILED" else EXIT_CODES[report.verdict]
    if args.command == "gui":
        if not DEFAULT_KB.exists():
            initialize_empty_kb()
            export_runtime_artifacts()
        run_gui()
        return 0
    if args.command == "build-kb":
        result = build_case_kb(args.case_dir, args.output, progress=lambda done, total: print(f"Indexed {done}/{total}", file=sys.stderr))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "OK" else 30
    if args.command == "benchmark":
        if not DEFAULT_KB.exists():
            initialize_empty_kb()
            export_runtime_artifacts()
        built_in = run_builtin_benchmark()
        result = {"built_in": built_in}
        passed = built_in["confusion"]["benign_phishing"] == 0 and built_in["metrics"]["phishing_plus_suspicious_recall"] == 1
        if args.case_dir:
            case = run_case_behavior_benchmark(args.case_dir, args.max_items, progress=lambda done, total: print(f"Behavior benchmark {done}/{total}", file=sys.stderr))
            result["case_behavior"] = case
            passed = passed and case["metrics"]["phishing_plus_suspicious_recall"] >= 0.90
        if args.spamassassin_ham:
            ham = run_spamassassin_ham_benchmark(args.spamassassin_ham, progress=lambda done: print(f"SpamAssassin ham {done}", file=sys.stderr))
            result["spamassassin_ham"] = ham
            passed = passed and ham["verdicts"].get("PHISHING", 0) == 0 and ham["analysis_statuses"].get("FAILED", 0) == 0
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if passed else 30
    if args.command == "doctor":
        result = doctor()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "OK" else 30
    return 30


if __name__ == "__main__":
    raise SystemExit(main())
