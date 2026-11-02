"""Bounded folder/ZIP/TAR processing without extracting archive paths to disk."""
from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import stat
import tarfile
import time
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .analyzer import Analyzer
from .models import AnalysisReport, AnalysisStatus
from .runtime import manifest, signature
from .utils import atomic_json

SUPPORTED = {".eml", ".mime", ".html", ".htm", ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".zip"}


@dataclass
class Item:
    name: str
    data: bytes | None = None
    error: str | None = None


def safe_member(name: str) -> bool:
    p = PurePosixPath(name.replace("\\", "/"))
    return bool(name) and not p.is_absolute() and ".." not in p.parts and not any(":" in part or "\x00" in part for part in p.parts)


def iter_items(source: Path, limits, *, extensions=None, pattern="*"):
    source = Path(source)
    allowed = {x.lower() if x.startswith('.') else '.' + x.lower() for x in extensions} if extensions else SUPPORTED
    selected = lambda n: Path(n).suffix.lower() in allowed and fnmatch.fnmatchcase(n, pattern)
    total = 0
    count = 0

    def check_size(size):
        nonlocal total, count
        count += 1
        if count > limits.max_archive_entries:
            raise ValueError("Batch item limit reached")
        total += size
        if size > limits.max_input_bytes:
            return "Input byte limit exceeded"
        if total > limits.max_total_extracted_bytes:
            raise ValueError("Batch total byte limit reached")
        return None

    if source.is_dir():
        # Symlinks, including directory symlinks/junctions, are never followed.
        import os
        for folder, dirs, files in os.walk(source, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not Path(folder, d).is_symlink() and not Path(folder, d).is_junction()) if hasattr(Path, 'is_junction') else sorted(d for d in dirs if not Path(folder, d).is_symlink())
            for filename in sorted(files):
                path = Path(folder, filename)
                name = path.relative_to(source).as_posix()
                if not selected(name):
                    continue
                if path.is_symlink():
                    yield Item(name, error="Symbolic link skipped")
                    continue
                try:
                    error = check_size(path.stat().st_size)
                    if error:
                        yield Item(name, error=error)
                    else:
                        with path.open('rb') as stream:
                            yield Item(name, stream.read(limits.max_input_bytes + 1))
                except OSError as exc:
                    yield Item(name, error=type(exc).__name__)
        return
    if not source.is_file():
        raise ValueError("Batch source must be a folder or archive")
    if source.stat().st_size > limits.max_total_extracted_bytes:
        raise ValueError("Archive input byte limit exceeded")
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as z:
            infos = z.infolist()
            if len(infos) > limits.max_archive_entries:
                raise ValueError("Archive entry limit reached")
            if sum(i.file_size for i in infos) > limits.max_archive_uncompressed_bytes:
                raise ValueError("Archive expansion byte limit reached")
            for info in sorted(infos, key=lambda i: i.filename):
                if info.is_dir() or not selected(info.filename):
                    continue
                error = check_size(info.file_size)
                mode = info.external_attr >> 16
                if not safe_member(info.filename) or stat.S_ISLNK(mode):
                    error = "Unsafe archive member skipped"
                if info.flag_bits & 1:
                    error = "Encrypted archive member skipped"
                if info.file_size / max(1, info.compress_size) > limits.max_compression_ratio:
                    error = "Compression ratio limit exceeded"
                if error:
                    yield Item(info.filename, error=error)
                    continue
                try:
                    with z.open(info) as stream:
                        data = stream.read(limits.max_input_bytes + 1)
                    yield Item(info.filename, data, error)
                except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
                    yield Item(info.filename, error=type(exc).__name__)
        return
    # Streaming TAR limits member count and decompression while reading.
    with tarfile.open(source, mode="r|*") as archive:
        members = expanded = 0
        for info in archive:
            members += 1
            expanded += info.size
            if members > limits.max_archive_entries or expanded > limits.max_archive_uncompressed_bytes or expanded / max(1, source.stat().st_size) > limits.max_compression_ratio:
                raise ValueError("TAR expansion limit reached")
            if not selected(info.name):
                continue
            error = check_size(info.size)
            if not info.isfile() or not safe_member(info.name):
                error = "Unsafe archive member skipped"
            stream = archive.extractfile(info) if not error else None
            data = stream.read(limits.max_input_bytes + 1) if stream else None
            if stream:
                stream.close()
            yield Item(info.name, data, error)


def run_batch(source: Path, analyzer: Analyzer, *, profile="quality", network="offline", browser_confirmation=None, output: Path | None = None, resume=False, extensions=None, pattern="*", store=None, progress=None, options=None) -> dict:
    if output and Path(output).resolve() == Path(source).resolve():
        raise ValueError('Batch output must not overwrite its input')
    started = time.perf_counter()
    settings = {"components":options or {}, "profile": profile, "network": network, "limits": repr(analyzer.limits), "runtime": manifest(analyzer.kb.path)}
    config_id = signature(settings)
    old = {}
    journal = Path(str(output) + '.jsonl') if output else None
    if resume and journal and journal.exists():
        for line in journal.read_text(encoding='utf-8').splitlines():
            try:
                row = json.loads(line)
            except ValueError:  # Interrupted last write; earlier rows survive.
                continue
            if row.get('config_id') == config_id and row.get('report', {}).get('analysis_status') == 'COMPLETE' and row.get('report', {}).get('configuration', {}).get('network_analysis_status') in {'NOT_REQUESTED', 'NOT_APPLICABLE', 'COMPLETE'}:
                if network != 'offline':
                    try:
                        age = (datetime.now(timezone.utc) - datetime.fromisoformat(row['analyzed_at'])).total_seconds()
                    except (ValueError, KeyError):
                        continue
                    if age > 3600:
                        continue
                old[row['id']] = row
    if journal:
        journal.parent.mkdir(parents=True, exist_ok=True)
        if not resume:
            journal.write_text('', encoding='utf-8')
        elif journal.exists() and journal.stat().st_size:
            with journal.open('rb') as stream:
                stream.seek(-1, 2)
                ended = stream.read(1) == b'\n'
            if not ended:
                with journal.open('a', encoding='utf-8') as stream:
                    stream.write('\n')
    rows, cache, warnings, occurrences = [], {}, [], Counter()
    try:
        for index, item in enumerate(iter_items(Path(source), analyzer.limits, extensions=extensions, pattern=pattern)):
            digest = hashlib.sha256(item.data).hexdigest() if item.data is not None else None
            occurrence = occurrences[item.name]
            occurrences[item.name] += 1
            identifier = signature({"name": item.name, "occurrence": occurrence, "sha256": digest, "error": item.error})[:32]
            tick = time.perf_counter()
            if identifier in old:
                row = copy.deepcopy(old[identifier]); row['resumed'] = True
            else:
                analysis = None
                key = (digest, Path(item.name).suffix.lower())
                duplicate = cache.get(key) if digest and not item.error else None
                if item.error:
                    report = AnalysisReport(analysis_status=AnalysisStatus.FAILED)
                    report.input = {"name": item.name, "sha256": digest}
                    report.warnings = [item.error]
                    payload = report.to_dict()
                elif duplicate:
                    payload = copy.deepcopy(duplicate['report'])
                    payload['input']['name'] = Path(item.name).name
                else:
                    analysis = analyzer.analyze(item.data, name=Path(item.name).name, profile=profile, network=network, browser_confirmation=browser_confirmation, options=options)
                    payload = analysis.to_dict()
                row = {"id": identifier, "source": item.name, "sha256": digest, "config_id": config_id, "analyzed_at": datetime.now(timezone.utc).isoformat(), "resumed": False, "duplicate_of": duplicate['id'] if duplicate else None, "report": payload}
                if store:
                    row['report_id'] = store.put(analysis or payload, identifier)
                    if duplicate and duplicate.get('report_id'):
                        store.clone_materials(duplicate['report_id'], row['report_id'])
                if journal:
                    with journal.open('a', encoding='utf-8') as stream:
                        stream.write(json.dumps(row, ensure_ascii=False) + '\n')
            row['processing_ms'] = round((time.perf_counter() - tick) * 1000, 3)
            if digest and not item.error and row['report']['analysis_status'] != 'FAILED':
                cache.setdefault((digest, Path(item.name).suffix.lower()), row)
            rows.append(row)
            if progress:
                progress(len(rows), row)
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        warnings.append(str(exc))
    elapsed = time.perf_counter() - started
    durations = sorted(r['processing_ms'] for r in rows if not r['resumed'] and not r.get('duplicate_of'))
    result = {"schema_version": "1.0", "created_at": datetime.now(timezone.utc).isoformat(), "source": str(source), "configuration": settings, "config_id": config_id, "batch_status": "PARTIAL" if warnings else "COMPLETE", "warnings": warnings,
              "statistics": {"items": len(rows), "resumed": sum(r['resumed'] for r in rows), "duplicates_reused": sum(bool(r.get('duplicate_of')) for r in rows), "elapsed_seconds": round(elapsed, 4), "items_per_minute": round(len(rows) * 60 / elapsed, 2) if elapsed else None, "p95_processing_ms": durations[min(len(durations)-1, int(.95 * len(durations)))] if durations else None,
                  "analysis_statuses": dict(Counter(r['report']['analysis_status'] for r in rows)), "verdicts": dict(Counter(r['report']['verdict'] for r in rows if r['report']['analysis_status'] != 'FAILED')), "network_statuses": dict(Counter(r['report']['configuration'].get('network_analysis_status', 'NOT_RUN') for r in rows))}, "results": rows}
    result['statistics']['reason_counts'] = dict(Counter(code for row in rows for code in {e['code'] for e in row['report']['reason_codes']}))
    result['statistics']['decisive_reason_counts'] = dict(Counter(code for row in rows for code in {e['code'] for e in row['report']['configuration'].get('decision',{}).get('reasons',[])}))
    if output:
        atomic_json(Path(output), result)
    return result
