"""The geometry detector and web UI share the same reviewed image gallery."""
import hashlib
import json
from functools import lru_cache
from pathlib import Path


def roots(gallery=None):
    from .config import RESOURCE_DIR,MODEL_DIR
    return [Path(gallery)] if gallery is not None else [RESOURCE_DIR/'logo-gallery',MODEL_DIR/'logo-references']


def reviewed_references(gallery=None):
    from .config import RESOURCE_DIR
    brand_revision=(RESOURCE_DIR/'brands.json').stat().st_mtime_ns
    result=[];seen=set()
    for root in roots(gallery):
        manifest=root/'manifest.jsonl'
        if not manifest.is_file():continue
        stat=manifest.stat()
        for row in _read_manifest(str(root.resolve()),stat.st_mtime_ns,stat.st_size,brand_revision):
            key=(row['brand'],row['sha256'])
            if key not in seen:seen.add(key);result.append(dict(row))
    return result


@lru_cache(maxsize=8)
def _read_manifest(root_string,mtime,size,brand_revision):
    from .brands import load_brands
    from .policy import official_host
    from .urltools import normalize_url
    brands={b['name']:b for b in load_brands()};result=[];seen=set()
    for root in [Path(root_string)]:
        manifest=root/'manifest.jsonl'
        if not manifest.is_file():continue
        if manifest.stat().st_size>4*1024*1024:raise ValueError('Gallery manifest byte limit')
        for line in manifest.read_text(encoding='utf-8').splitlines()[:4000]:
            if not line.strip():continue
            row=json.loads(line);brand=brands.get(row.get('brand'))
            if not brand or row.get('reviewed') is not True:continue
            if not official_host(normalize_url(row['source_url']).host,brand['domains']):continue
            path=(root/row['path']).resolve()
            if not path.is_relative_to(root.resolve()) or not path.is_file() or path.stat().st_size>10*1024*1024:continue
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            if row.get('sha256') and row['sha256']!=digest:continue
            if (row['brand'],digest) in seen:continue
            seen.add((row['brand'],digest))
            result.append({**row,'sha256':digest,'_file':str(path)})
    return result


def import_gallery(source):
    """Import reviewed symbols for geometry search, without a neural index."""
    from .config import MODEL_DIR
    source=Path(source);records=reviewed_references(source)
    if not records:raise ValueError('No reviewed logo references')
    destination=MODEL_DIR/'logo-references';destination.mkdir(parents=True,exist_ok=True)
    existing=reviewed_references(destination)
    unique={(r['brand'],r['sha256']):r for r in existing}
    for r in records:
        import io
        from PIL import Image
        with Image.open(r['_file']) as image:
            if image.width*image.height>30_000_000:raise ValueError('Logo pixel limit')
            output=io.BytesIO();image.convert('RGBA').save(output,'PNG')
        blob=output.getvalue();digest=hashlib.sha256(blob).hexdigest()
        name=digest+'.png';(destination/name).write_bytes(blob)
        unique[(r['brand'],digest)]={**r,'path':name,'sha256':digest,'original_sha256':r['sha256']}
    rows=[{k:v for k,v in r.items() if k!='_file'} for r in unique.values()]
    temporary=destination/'manifest.jsonl.tmp'
    temporary.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
    temporary.replace(destination/'manifest.jsonl')
    return {'references':len(rows),'imported':len(rows)-len(existing),'brands':len({r['brand'] for r in rows})}
