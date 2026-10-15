from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import sqlite3
import sys
import re
from contextlib import closing
from pathlib import Path

from .analyzer import Analyzer, EXIT_CODES
from .benchmark import run_builtin_benchmark
from .config import ARTIFACT_DIR, DEFAULT_KB, MODEL_DIR, PROJECT_ROOT
from .kb import build_case_kb, export_runtime_artifacts, initialize_empty_kb
from .evaluation import run_case_behavior_benchmark
from .external_eval import run_spamassassin_ham_benchmark


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="antiphish", description="Локальный precision-first анализатор фишинга")
    root.add_argument('--log-json', action='store_true', help='структурированные журналы анализа в stderr')
    from . import __version__
    root.add_argument("--version", action="version", version="AntiPhish " + __version__)
    sub = root.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="проанализировать файл, URL или stdin")
    analyze.add_argument("source", help="путь, URL или -")
    analyze.add_argument("--profile", choices=("fast", "quality", "deep"), default="quality")
    analyze.add_argument("--network", choices=("offline", "http", "browser"), default="http")
    analyze.add_argument("--confirm-browser-risk")
    analyze.add_argument("--json", action="store_true")
    analyze.add_argument("--output", type=Path)
    analyze.add_argument("--kb", type=Path, default=DEFAULT_KB)
    analyze.add_argument('--persist', action='store_true', help='сохранить отчёт в локальной истории')
    gui = sub.add_parser("gui", help="открыть демонстрационный GUI")
    build = sub.add_parser("build-kb", help="построить KB напрямую из ZIP кейса")
    build.add_argument("--case-dir", required=True, type=Path)
    build.add_argument("--output", type=Path, default=DEFAULT_KB)
    benchmark = sub.add_parser("benchmark", help="запустить встроенную или case-wide регрессионную проверку")
    benchmark.add_argument("--case-dir", type=Path, help="дополнительно проверить HTML кейса с пустой KB")
    benchmark.add_argument("--max-items", type=int, help="ограничить число HTML только для быстрого smoke-run")
    benchmark.add_argument("--spamassassin-ham", type=Path, action="append", default=[], help="официальный easy/hard ham .tar.bz2; можно повторить")
    sub.add_parser("doctor", help="проверить окружение")
    sub.add_parser('serve', help='внутренний FastAPI на 127.0.0.1:8000; Swagger /docs')
    domains = sub.add_parser('import-domains', help='CSV доменов как непроверенный контекст, без пропуска анализа')
    domains.add_argument('source', type=Path)
    domains.add_argument('--kb', type=Path, default=DEFAULT_KB)
    dataset = sub.add_parser('benchmark-dataset', help='оценить ZIP с manifest.jsonl, без обучения по его меткам')
    dataset.add_argument('archive', type=Path)
    dataset.add_argument('--kb', type=Path, default=DEFAULT_KB)
    dataset.add_argument('--profile', choices=('fast', 'quality', 'deep'), default='quality')
    dataset.add_argument('--network', choices=('offline', 'http'), default='offline')
    dataset.add_argument('--output', required=True, type=Path)
    audit = sub.add_parser('audit-dataset', help='проверка корпуса, очередь разметки и необязательная проверка текущих URL')
    audit.add_argument('archive', type=Path)
    audit.add_argument('--output-dir', required=True, type=Path)
    audit.add_argument('--check-links', action='store_true')
    audit.add_argument('--max-urls', type=int, default=100)
    capture = sub.add_parser('capture-urls', help='сохранить текущие страницы из файла URL для повторного локального анализа')
    capture.add_argument('urls', type=Path, help='по одному URL на строку')
    capture.add_argument('--output-dir', required=True, type=Path)
    capture.add_argument('--max-urls', type=int, default=100)
    batch = sub.add_parser('batch', help='пакетный анализ папки/ZIP/TAR, по одному отчёту на объект')
    batch.add_argument('source', type=Path)
    batch.add_argument('--kb', type=Path, default=DEFAULT_KB)
    batch.add_argument('--profile', choices=('fast', 'quality', 'deep'), default='quality')
    batch.add_argument('--network', choices=('offline', 'http', 'browser'), default='offline')
    batch.add_argument('--confirm-browser-risk')
    batch.add_argument('--extensions', nargs='+')
    batch.add_argument('--pattern', default='*')
    batch.add_argument('--output', required=True, type=Path)
    batch.add_argument('--resume', action='store_true')
    batch.add_argument('--persist', action='store_true')
    sub.add_parser("setup-ocr", help="скачать и проверить локальные ONNX-модели русского OCR")
    sub.add_parser('setup-text-model', help='скачать закреплённый многоязычный классификатор; включается отдельно, только наблюдения')
    logos = sub.add_parser('index-logos', help='индекс проверенных изображений брендов, manifest.jsonl в папке')
    logos.add_argument('gallery', type=Path)
    match_logo = sub.add_parser('match-logo', help='визуальные кандидаты бренда; не вердикт фишинга')
    match_logo.add_argument('image', type=Path)
    feeds = sub.add_parser("update-feeds", help="скачать локальные снимки фишинговых URL")
    feeds.add_argument("--kb", type=Path, default=DEFAULT_KB)
    feeds.add_argument("--provider", choices=("phishing-database", "openphish", "phishtank"), action="append")
    feed_status = sub.add_parser("feed-status", help="показать возраст локальных снимков")
    feed_status.add_argument("--kb", type=Path, default=DEFAULT_KB)
    corpus = sub.add_parser("benchmark-corpus", help="проверка писем и цепочек по записанным страницам ZIP, без сети и IOC")
    corpus.add_argument("archive", type=Path)
    corpus.add_argument("--profile", choices=("fast", "quality"), default="quality")
    corpus.add_argument("--max-items", type=int)
    corpus.add_argument("--output", type=Path)
    ingest = sub.add_parser("import-corpus", help="добавить связанные образцы из ZIP без автоматической блокировки их хешей")
    ingest.add_argument("archive", type=Path)
    ingest.add_argument("--kb", type=Path, default=DEFAULT_KB)
    learn = sub.add_parser("learn-template", help="добавить размеченный HTML-образец, в том числе отрицательный")
    learn.add_argument("source", type=Path)
    learn.add_argument("--label", choices=("benign", "phishing"), required=True)
    learn.add_argument("--kb", type=Path, default=DEFAULT_KB)
    return root


def _print_human(report) -> None:
    if report.analysis_status.value == "FAILED":
        print("Анализ не выполнен; вердикт недоступен.")
    else:
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
    if report.verdict.value == "NOT_DETECTED" and report.analysis_status.value != "FAILED":
        print("NOT_DETECTED означает отсутствие достаточных доказательств, а не гарантию легитимности.")


def doctor() -> dict:
    modules = ["lxml", "PIL", "fitz", "cv2", "playwright", "idna"]
    checks = {name: importlib.util.find_spec(name) is not None for name in modules}
    from .network import browser_executable
    from playwright.sync_api import sync_playwright
    try:
        executable = browser_executable()
        if not executable:
            with sync_playwright() as pw:
                executable = pw.chromium.executable_path
    except Exception:
        executable = ''
    edge = Path(executable) if executable else Path('__browser_not_installed__')
    kb_ok = False
    kb_rows = 0
    if DEFAULT_KB.exists():
        try:
            with closing(sqlite3.connect(DEFAULT_KB)) as con:
                kb_rows = con.execute("SELECT count(*) FROM known_hashes").fetchone()[0]
                kb_ok = True
        except sqlite3.Error:
            pass
    deep = {"qwen_installed": (MODEL_DIR / "Qwen3.5-4B").is_dir(), "siglip2_installed": (MODEL_DIR / "siglip2-base-patch16-224").is_dir(), "torch": None, "cuda_available": False, "cuda_device": None}
    if importlib.util.find_spec("torch"):
        try:
            import torch
            deep.update(torch=torch.__version__, cuda_available=torch.cuda.is_available(), cuda_device=torch.cuda.get_device_name(0) if torch.cuda.is_available() else None)
        except Exception as exc:
            deep["error"] = f"{type(exc).__name__}: {exc}"
    from .reputation import status
    from .kb import KnowledgeBase
    from .ocr import status as ocr_status
    return {
        "status": "OK" if all(checks.values()) else "DEGRADED",
        "python": sys.version, "platform": platform.platform(), "project_root": str(PROJECT_ROOT),
        "modules": checks, "edge": {"path": str(edge), "available": edge.exists()},
        "knowledge_base": {"path": str(DEFAULT_KB), "valid": kb_ok, "known_hashes": kb_rows},
        "reputation": status(KnowledgeBase(DEFAULT_KB).reputation_path), "ocr": ocr_status(), "deep": deep,
        "privacy": "models and reputation are local; HTTP/browser modes visit message links; raw inputs are not persisted automatically",
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.log_json:
        from .logging import configure
        configure()
    if args.command in {'index-logos','match-logo'}:
        from .logos import build_index, match_image
        result = build_index(args.gallery) if args.command == 'index-logos' else match_image(args.image.read_bytes())
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0
    if args.command == 'setup-text-model':
        from .textmodel import setup
        print(json.dumps(setup(),ensure_ascii=False,indent=2))
        return 0
    if args.command == 'audit-dataset':
        from .dataset import audit_dataset
        print(json.dumps(audit_dataset(args.archive,output_dir=args.output_dir,check_links=args.check_links,max_urls=args.max_urls),ensure_ascii=False,indent=2))
        return 0
    if args.command == 'capture-urls':
        from .capture import check_urls
        from .utils import atomic_json
        urls = args.urls.read_text(encoding='utf-8-sig').splitlines()
        result = check_urls([u.strip() for u in urls if u.strip()], output_dir=args.output_dir, max_urls=args.max_urls)
        atomic_json(args.output_dir/'captures.json',result)
        print(json.dumps({k:v for k,v in result.items() if k != 'rows'},ensure_ascii=False,indent=2))
        return 0
    if args.command == 'benchmark-dataset':
        from .dataset import benchmark_dataset
        result = benchmark_dataset(args.archive, Analyzer(args.kb), profile=args.profile, network=args.network, output=args.output, progress=lambda n: print(f'Evaluated {n}', file=sys.stderr))
        print(json.dumps({k:v for k,v in result.items() if k != 'rows'}, ensure_ascii=False, indent=2))
        return 0
    if args.command == 'import-domains':
        from .domains import import_domains
        print(json.dumps(import_domains(args.source, args.kb.with_suffix('.domains.sqlite')), ensure_ascii=False, indent=2))
        return 0
    if args.command == 'serve':
        from .api import main as serve
        serve()
        return 0
    if args.command == 'batch':
        from .batch import run_batch
        from .store import ReportStore
        from .config import REPORT_DIR
        try:
            result = run_batch(args.source, Analyzer(args.kb), profile=args.profile, network=args.network, browser_confirmation=args.confirm_browser_risk, extensions=args.extensions, pattern=args.pattern, output=args.output, resume=args.resume, store=ReportStore(REPORT_DIR / 'history.sqlite') if args.persist else None, progress=lambda count, row: print(f"Processed {count}: {row['report']['analysis_status']}", file=sys.stderr) if count % 50 == 0 else None)
        except ValueError as exc:
            print(json.dumps({'batch_status':'FAILED','error':str(exc)},ensure_ascii=False))
            return 30
        print(json.dumps({k: v for k, v in result.items() if k != 'results'}, ensure_ascii=False, indent=2))
        return 30 if result['batch_status'] != 'COMPLETE' or result['statistics']['analysis_statuses'].get('FAILED') or not result['statistics']['items'] else 0
    if args.command == "setup-ocr":
        from .ocr import setup_models
        try:
            result = setup_models(progress=lambda message: print(message, file=sys.stderr))
        except Exception as exc:
            print(json.dumps({"status": "FAILED", "error": type(exc).__name__}, indent=2))
            return 30
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "READY" else 30
    if args.command in {"import-corpus", "learn-template"}:
        from .templates import import_corpus, learn_file
        if not args.kb.exists():
            initialize_empty_kb(args.kb)
        result = import_corpus(args.archive, args.kb, progress=lambda done: print(f"Corpus: {done}",file=sys.stderr)) if args.command == "import-corpus" else learn_file(args.source,args.kb,args.label,args.source.name)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0
    if args.command == "benchmark-corpus":
        from .corpus import benchmark_corpus
        result = benchmark_corpus(args.archive, max_items=args.max_items, output=args.output, profile=args.profile, progress=lambda done: print(f"Corpus: {done}", file=sys.stderr))
        print(json.dumps({k:v for k,v in result.items() if k != "rows"}, ensure_ascii=False, indent=2))
        return 0
    if args.command in {"update-feeds", "feed-status"}:
        from .reputation import update_feeds, status
        if args.command == "update-feeds":
            if not args.kb.exists():
                initialize_empty_kb(args.kb)
            result = update_feeds(args.kb.with_suffix(".reputation.sqlite"), args.provider, progress=lambda value: print(value, file=sys.stderr))
        else:
            separate = args.kb.with_suffix(".reputation.sqlite")
            result = status(separate if separate.exists() else args.kb)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] in {"OK", "READY"} else 30
    if args.command == "analyze":
        if not args.kb.exists():
            initialize_empty_kb(args.kb)
            export_runtime_artifacts(args.kb)
        from .config import DEFAULT_LIMITS
        source = sys.stdin.buffer.read(DEFAULT_LIMITS.max_input_bytes + 1) if args.source == "-" else args.source
        from .utils import pasted_name
        name = pasted_name(source,"stdin") if isinstance(source,bytes) else None
        report = Analyzer(args.kb).analyze(source, name=name, profile=args.profile, network=args.network, browser_confirmation=args.confirm_browser_risk)
        payload = report.to_dict()
        if args.persist:
            from .store import ReportStore
            from .config import REPORT_DIR
            payload['report_id'] = ReportStore(REPORT_DIR/'history.sqlite').put(payload)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            _print_human(report)
        return 30 if report.analysis_status.value == "FAILED" else EXIT_CODES[report.verdict]
    if args.command == "gui":
        from .gui import run_gui
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
            # Provider-labelled captures include legitimate/error pages;
            # their alert rate is not a ground-truth recall acceptance gate.
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
