"""Record a local acceptance stand without importing data or changing the KB."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> dict:
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return {'name': path.name, 'bytes': path.stat().st_size, 'sha256': value.hexdigest()}


def git(*args: str) -> str:
    result = subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=30)
    return result.stdout.strip() if result.returncode == 0 else ''


def inventory(kb: Path) -> dict:
    if not kb.is_file():
        return {'present': False}
    counts = {}
    with sqlite3.connect(kb.resolve().as_uri() + '?mode=ro', uri=True) as con:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for name in ('brands', 'known_hashes', 'fingerprints', 'url_iocs',
                     'behavior_templates', 'reviewed_samples', 'source_stats'):
            if name in tables:
                counts[name] = con.execute('SELECT count(*) FROM "' + name + '"').fetchone()[0]
    return {'present': True, 'file': digest(kb), 'counts': counts,
            'warning': 'A live SQLite file hash is provisional. Stop writers and use a SQLite backup for the final frozen stand.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--kb', type=Path, help='Optional local KB; opened read-only')
    parser.add_argument('--dataset', type=Path, action='append', default=[])
    parser.add_argument('--split', type=Path)
    parser.add_argument('--config', type=Path)
    args = parser.parse_args()
    inputs = [*args.dataset, *([args.split] if args.split else []),
              *([args.config] if args.config else [])]
    for path in inputs + ([args.kb] if args.kb else []):
        if not path.is_file():
            parser.error('Input file not found: ' + str(path))
    # Never overwrite an input, source, or an already saved stand snapshot.
    destination = args.output.resolve()
    protected = {p.resolve() for p in inputs + ([args.kb] if args.kb else [])}
    if destination in protected or destination.is_relative_to(ROOT / 'src') or destination.exists():
        parser.error('Use a new output path outside source files and inputs')
    brands = json.loads((ROOT / 'resources/brands.json').read_text(encoding='utf-8'))['brands']
    logo_meta = ROOT / 'resources/logo-gallery/logo-index.json'
    refs = json.loads(logo_meta.read_text(encoding='utf-8')).get('references', []) if logo_meta.exists() else []
    tracked = git('ls-files').splitlines()
    current_candidates = [p for p in tracked if p.startswith(('artifacts/', 'reports/', 'data/private/'))
                          or p.endswith(('.eml', '.sqlite')) or Path(p).name == '.env']
    historical = sorted(set(git('log', '--all', '--format=', '--name-only', '--',
                                'artifacts/', 'reports/', 'data/private/', '*.eml', '.env').splitlines()) - {''})
    source_files = [*sorted((ROOT / 'src/antiphish').rglob('*.py')),
                    *sorted((ROOT / 'src/antiphish/web').glob('*')),
                    *sorted((ROOT / 'resources').rglob('*')),
                    *sorted((ROOT / 'tests').glob('*.py')),
                    *sorted((ROOT / 'scripts').glob('*.py'))]
    source_files += [ROOT / name for name in ('pyproject.toml', 'setup.py', 'MANIFEST.in',
                                             'Dockerfile', 'compose.yaml', '.env.example', 'README.md')]
    files = {p.relative_to(ROOT).as_posix(): digest(p) for p in source_files if p.is_file()}
    source_hash = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    from antiphish import __version__
    from antiphish.runtime import manifest
    payload = {
        'kind': 'preliminary_stand_snapshot', 'official_acceptance': False,
        'utc': datetime.now(timezone.utc).isoformat(),
        'application_version': __version__, 'git_head': git('rev-parse', 'HEAD'),
        'git_exact_tag': git('describe', '--tags', '--exact-match'),
        'working_tree_dirty': bool(git('status', '--porcelain')),
        'python': platform.python_version(), 'system': platform.platform(),
        'runtime': manifest(args.kb or ROOT / 'artifacts/knowledge.sqlite'),
        'source_manifest_sha256': source_hash, 'files': files,
        'brand_catalog': {'records': len(brands), 'active': sum(bool(b.get('active')) for b in brands),
                          'logo_references': len(refs), 'reference_brands': len({r['brand'] for r in refs}),
                          'customer_175_coverage': 'requires_manual_mapping_and_reference_review'},
        'knowledge': inventory(args.kb) if args.kb else {'not_requested': True},
        'datasets': [digest(p) for p in args.dataset],
        'split': digest(args.split) if args.split else None,
        'configuration': digest(args.config) if args.config else None,
        'repository_review': {'tracked_data_candidates': current_candidates,
                              'historical_data_candidates': historical,
                              'note': 'Paths require a confidentiality review; this is not a complete secret scan or a claim of a clean Git history.'},
        'unresolved': ['No held-out DOM split file supplied' if not args.split else 'Split approval and independence require human review',
                       'K-2 element-level gold annotations are not measured by this script',
                       'Native Linux GPU, recovery and per-type performance acceptance runs remain separate'],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'application_version': __version__,
                      'active_brands': payload['brand_catalog']['active'],
                      'official_acceptance': False}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
