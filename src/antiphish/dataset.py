"""Evaluate manifest-labelled captures without learning from test labels."""
from __future__ import annotations

import hashlib
import json
import math
import random
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import Analyzer
from .batch import safe_member
from .config import DEFAULT_LIMITS
from .runtime import manifest, signature
from .utils import atomic_json


def interval(successes: int, trials: int) -> list[float] | None:
    if not trials:
        return None
    z, p = 1.959963984540054, successes / trials
    denom = 1 + z*z/trials
    center = (p + z*z/(2*trials)) / denom
    half = z * math.sqrt(p*(1-p)/trials + z*z/(4*trials*trials)) / denom
    return [max(0., center-half), min(1., center+half)]


def metrics(rows: list[dict]) -> dict:
    known = [r for r in rows if r.get('label') in {'phishing', 'benign'}]
    positive = [r for r in known if r['label'] == 'phishing']
    negative = [r for r in known if r['label'] == 'benign']
    result = {'labelled': len(known), 'unknown_label': len(rows)-len(known), 'statuses': dict(Counter(r['status'] for r in rows)), 'network_statuses': dict(Counter(r.get('network_status', 'NOT_REQUESTED') for r in rows))}
    result['completed_fraction'] = sum(r['status'] == 'COMPLETE' for r in rows) / len(rows) if rows else None
    for name, alerts in (('strict_phishing', {'PHISHING'}), ('review_or_phishing', {'PHISHING', 'SUSPICIOUS'})):
        tp = sum(r['verdict'] in alerts and r['status'] != 'FAILED' for r in positive)
        fp = sum(r['verdict'] in alerts and r['status'] != 'FAILED' for r in negative)
        # Failure/partial is never silently removed to improve recall. Publish
        # availability separately and retain all labelled cases in denominators.
        groups = defaultdict(list)
        for row in known:
            groups[(row['label'], row.get('group_id') or row['id'])].append(row)
        weighted = {}
        for label in ('phishing', 'benign'):
            values = [sum(r['verdict'] in alerts and r['status'] != 'FAILED' for r in group)/len(group) for (truth, _), group in groups.items() if truth == label]
            weighted[label] = sum(values)/len(values) if values else None
        result[name] = {'tp': tp, 'fp': fp, 'fn': len(positive)-tp, 'tn': len(negative)-fp, 'recall': tp/len(positive) if positive else None, 'fpr': fp/len(negative) if negative else None, 'precision': tp/(tp+fp) if tp+fp else None,
                        'recall_wilson95': interval(tp, len(positive)), 'fpr_wilson95': interval(fp, len(negative)), 'group_weighted_recall': weighted['phishing'], 'group_weighted_fpr': weighted['benign']}
    return result


def paired_comparison(before: list[dict], after: list[dict], *, seed=20261007, repeats=2000) -> dict:
    a, b = {r['id']: r for r in before}, {r['id']: r for r in after}
    if a.keys() != b.keys() or any(a[k].get('label') != b[k].get('label') or a[k].get('sha256') != b[k].get('sha256') for k in a):
        raise ValueError('Paired comparison requires identical IDs, labels and input hashes')
    rng, output = random.Random(seed), {}
    for label in ('benign', 'phishing'):
        groups = defaultdict(list)
        for identifier in a:
            if a[identifier]['label'] == label:
                def alarm(row):
                    return int(row['verdict'] in {'SUSPICIOUS', 'PHISHING'} and row['status'] != 'FAILED')
                groups[a[identifier].get('group_id') or identifier].append(alarm(b[identifier])-alarm(a[identifier]))
        differences = [sum(values)/len(values) for values in groups.values()]
        bootstrap = sorted(sum(rng.choices(differences, k=len(differences)))/len(differences) for _ in range(repeats)) if differences else []
        output[label] = {'groups': len(differences), 'group_weighted_alarm_change': sum(differences)/len(differences) if differences else None, 'cluster_bootstrap95': [bootstrap[int(.025*repeats)], bootstrap[min(repeats-1, int(.975*repeats))]] if bootstrap else None}
    return {'seed': seed, 'repeats': repeats, 'comparison': output, 'note': 'Same inspected test set; post-change results are development evidence, not a new zero-shot test.'}


def read_manifest(archive):
    candidates = [i for i in archive.infolist() if Path(i.filename).name == 'manifest.jsonl']
    if len(candidates) != 1 or candidates[0].file_size > 20 * 1024 * 1024:
        raise ValueError('Archive needs exactly one bounded manifest.jsonl')
    entry = candidates[0]
    rows = [json.loads(line) for line in archive.read(entry).decode('utf-8-sig').splitlines() if line.strip()]
    ids = [r['id'] for r in rows]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate manifest IDs')
    return entry.filename.rsplit('/', 1)[0] + '/' if '/' in entry.filename else '', rows


def benchmark_dataset(archive_path: Path, analyzer: Analyzer, *, profile='quality', network='offline', output=None, progress=None) -> dict:
    started = time.perf_counter()
    rows, audit = [], {}
    with zipfile.ZipFile(archive_path) as archive:
        if len(archive.infolist()) > DEFAULT_LIMITS.max_archive_entries or sum(i.file_size for i in archive.infolist()) > DEFAULT_LIMITS.max_archive_uncompressed_bytes:
            raise ValueError('Dataset archive limits exceeded')
        prefix, records = read_manifest(archive)
        selected = [r for r in records if r.get('subset') in {None, 'validation', 'test'}]
        if len(selected) > DEFAULT_LIMITS.max_archive_entries:
            raise ValueError('Dataset row limit reached')
        for record in selected:
            row = {key: record.get(key) for key in ('id','label','source','language','brand','group_id','year','review_status','label_basis')}
            row.update(sha256=None, verdict='NOT_DETECTED', status='FAILED', network_status='NOT_RUN', reasons=[], ms=None)
            try:
                path = record.get('evaluation_path') or record['path']
                if not safe_member(path):
                    raise ValueError('Unsafe dataset path')
                info = archive.getinfo(prefix + path)
                if info.file_size > DEFAULT_LIMITS.max_input_bytes or info.file_size / max(1, info.compress_size) > DEFAULT_LIMITS.max_compression_ratio:
                    raise ValueError('Unsafe dataset member size/ratio')
                data = archive.read(info)
                digest = hashlib.sha256(data).hexdigest()
                row['sha256'] = digest
                expected_hash = record.get('sha256_evaluation') or record.get('sha256')
                if expected_hash and digest != expected_hash:
                    raise ValueError('Dataset checksum mismatch')
                report = analyzer.analyze(data, name=Path(path).name, profile=profile, network=network, base_url=record.get('url') if Path(path).suffix.lower() in {'.html', '.htm'} else None)
                row.update(verdict=report.verdict.value, status=report.analysis_status.value, network_status=report.configuration.get('network_analysis_status'), reasons=[e.code for e in report.reason_codes], decisive_reasons=[e['code'] for e in report.configuration.get('decision',{}).get('reasons',[])], ms=report.timings_ms.get('total'))
            except (KeyError, ValueError, OSError, zipfile.BadZipFile) as exc:
                # A corrupt/missing object remains a failed labelled trial;
                # neither quietly drop it nor abort the remaining dataset.
                row['error'] = type(exc).__name__ + ': ' + str(exc)
            rows.append(row)
            if progress and len(rows) % 100 == 0:
                progress(len(rows))
        audit = {'labels': dict(Counter(r.get('label') for r in selected)), 'sources': dict(Counter(r.get('source') for r in selected)), 'years': dict(Counter(str(r.get('year')) for r in selected)), 'groups': len({r.get('group_id') or r['id'] for r in selected}), 'unverified_labels': sum(r.get('review_status') != 'independently_verified' for r in selected), 'unique_inputs': len({r['sha256'] for r in rows}), 'phishing_without_url_hosts': sum(r.get('label') == 'phishing' and not r.get('url_hosts') for r in selected)}
    output_data = {'utc': datetime.now(timezone.utc).isoformat(), 'archive_sha256': hashlib.sha256(Path(archive_path).read_bytes()).hexdigest(), 'runtime': manifest(analyzer.kb.path), 'profile': profile, 'network': network, 'elapsed_seconds': time.perf_counter()-started, 'audit': audit, 'metrics': metrics(rows), 'by_source': {value: metrics([r for r in rows if r['source'] == value]) for value in sorted({r['source'] for r in rows if r['source']})}, 'by_language': {value: metrics([r for r in rows if r['language'] == value]) for value in sorted({r['language'] for r in rows if r['language']})}, 'rows': rows,
                   'limitations': ['Metrics compare against supplied labels, not independently established truth.', 'Inspect source, campaign/template overlap and age; source SHA disjointness alone does not prove zero-shot independence.', 'Working HTTP response is not a phishing label; an unavailable website is not benign.', 'Wilson intervals assume independent examples; group-weighted estimates and paired cluster bootstrap address some correlations.']}
    output_data['independently_reviewed_metrics'] = metrics([r for r in rows if r.get('review_status') == 'independently_verified'])
    if output:
        atomic_json(Path(output), output_data)
    return output_data


def audit_dataset(archive_path: Path, *, output_dir: Path, check_links=False, max_urls=100) -> dict:
    """Produce a review queue and deterministic group split, preserving originals."""
    from .extractors import extract_any
    from .analyzer import _network_candidate_priority
    from .urltools import normalize_url
    output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
    observations, urls, groups = [], [], {}
    with zipfile.ZipFile(archive_path) as archive:
        prefix, rows = read_manifest(archive)
        if len(rows) > DEFAULT_LIMITS.max_archive_entries or sum(i.file_size for i in archive.infolist()) > DEFAULT_LIMITS.max_archive_uncompressed_bytes:
            raise ValueError('Dataset limits reached')
        for row in rows:
            if row.get('subset') not in {'validation', 'test', None}:
                continue
            path = row.get('evaluation_path') or row['path']
            if not safe_member(path):
                raise ValueError('Unsafe dataset path')
            info = archive.getinfo(prefix + path)
            if info.file_size > DEFAULT_LIMITS.max_input_bytes or info.file_size / max(1, info.compress_size) > DEFAULT_LIMITS.max_compression_ratio:
                raise ValueError('Unsafe dataset member')
            data = archive.read(info)
            extracted = extract_any(data, Path(path).name, None, DEFAULT_LIMITS, quality=False)
            destinations = list(dict.fromkeys(u.navigation_url or u.normalized for u in extracted.urls if _network_candidate_priority(u, False) is not None and (u.navigation_url or u.normalized)))
            urls.extend(destinations)
            placeholder = [u for u in destinations if normalize_url(u).host in {'example.com', 'example.net', 'example.org'} or normalize_url(u).host.endswith(('.test', '.example', '.invalid'))]
            group = row.get('group_id') or row.get('content_fingerprint') or row['id']
            slot = int(hashlib.sha256(str(group).encode()).hexdigest()[:8],16) % 10
            split = 'development' if slot < 6 else 'validation' if slot < 8 else 'held_out'
            problems = []
            if row.get('review_status') != 'independently_verified': problems.append('label_not_independently_verified')
            try:
                if row.get('year') and int(row['year']) < datetime.now(timezone.utc).year-1: problems.append('old_email')
            except (ValueError, TypeError):
                problems.append('invalid_year')
            if row.get('label') == 'phishing' and placeholder: problems.append('placeholder_destination')
            if row.get('label') == 'phishing' and not destinations: problems.append('no_navigable_url')
            observations.append({'id': row['id'], 'label': row.get('label'), 'review_status': 'needs_review', 'original_review_status': row.get('review_status'), 'source': row.get('source'), 'path': path, 'sha256': hashlib.sha256(data).hexdigest(), 'group_id': group, 'recommended_split': split, 'problems': problems, 'destinations': [normalize_url(u).redacted for u in destinations], 'placeholder_destinations': len(placeholder)})
    from collections import Counter
    result = {'archive_sha256': hashlib.sha256(Path(archive_path).read_bytes()).hexdigest(), 'rows': len(observations), 'problem_counts': dict(Counter(p for r in observations for p in r['problems'])), 'split_counts': dict(Counter(r['recommended_split'] for r in observations)), 'note': 'This archive has already been evaluated: its proposed held_out split is not an independent unseen test. Retain it as development/regression data; reserve new campaigns and later captures for final tests.'}
    (output_dir/'review-queue.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in observations), encoding='utf-8')
    if check_links:
        from .capture import check_urls
        health = check_urls(urls, output_dir=output_dir/'private-captures', max_urls=max_urls)
        atomic_json(output_dir/'link-health.json', health)
        result['link_health'] = {k:v for k,v in health.items() if k != 'rows'}
    atomic_json(output_dir/'audit.json', result)
    return result
