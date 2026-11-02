"""Reference-image matching with the installed SigLIP2; no safety verdict."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

from .config import MODEL_DIR, logo_index_path
from .deep import _load_siglip, rgb_image
from .utils import atomic_json

INDEX = MODEL_DIR / 'logo-index.npz'


def embeddings(images):
    import torch
    import numpy as np
    processor, model = _load_siglip(str(MODEL_DIR/'siglip2-base-patch16-224'))
    inputs = processor(images=images, return_tensors='pt').to(model.device)
    with torch.inference_mode():
        output = model.get_image_features(**inputs)
        output = output.pooler_output if hasattr(output, 'pooler_output') else output
        output = torch.nn.functional.normalize(output.float(), dim=-1)
    return output.cpu().numpy().astype(np.float32)


def build_index(gallery: Path, output: Path = INDEX) -> dict:
    """Gallery manifest JSONL: {path,brand,source_url,reviewed:true}."""
    from PIL import Image
    from .brands import load_brands
    from .policy import official_host
    from .urltools import normalize_url
    import numpy as np
    gallery = Path(gallery)
    records = [json.loads(line) for line in (gallery/'manifest.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    if len(records) > 2000:
        raise ValueError('Logo reference limit reached')
    catalog = {b['name']:b for b in load_brands()}
    accepted, vectors, pending = [], [], []
    for record in records:
        brand = catalog.get(record.get('brand'))
        if not brand or record.get('reviewed') is not True or not official_host(normalize_url(record['source_url']).host, brand['domains']):
            raise ValueError('Logo needs a reviewed brand and official source URL')
        path = (gallery/record['path']).resolve()
        if not path.is_relative_to(gallery.resolve()) or path.stat().st_size > 10*1024*1024:
            raise ValueError('Unsafe logo reference path/size')
        with Image.open(path) as image:
            if image.width*image.height > 30000000:
                raise ValueError('Logo pixel limit reached')
            image = rgb_image(image); image.thumbnail((768,768))
            pending.append(image.copy())
        if len(pending) >= 16:
            vectors.extend(embeddings(pending))
            pending.clear()
        accepted.append({**record, 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    if pending:
        vectors.extend(embeddings(pending))
    if not vectors:
        raise ValueError('Gallery is empty')
    output.parent.mkdir(parents=True,exist_ok=True)
    temporary = output.with_suffix('.tmp.npz')
    np.savez_compressed(temporary, embeddings=np.stack(vectors))
    temporary.replace(output)
    metadata = {'version':'1.1','preprocessing':'rgb-white-alpha-v1', 'model':'siglip2-base-patch16-224', 'references':accepted, 'index_sha256':hashlib.sha256(output.read_bytes()).hexdigest(), 'model_config_sha256':hashlib.sha256((MODEL_DIR/'siglip2-base-patch16-224/config.json').read_bytes()).hexdigest(), 'calibrated':False, 'blocking':False}
    atomic_json(output.with_suffix('.json'),metadata)
    return metadata


def match_image(blob: bytes, index: Path | None = None) -> dict:
    index = Path(index) if index is not None else logo_index_path()
    import numpy as np
    from PIL import Image
    metadata=json.loads(index.with_suffix('.json').read_text(encoding='utf-8'))
    if metadata.get('preprocessing')!='rgb-white-alpha-v1':
        raise ValueError('Logo preprocessing changed; rebuild using index-logos')
    if metadata['index_sha256'] != hashlib.sha256(index.read_bytes()).hexdigest() or metadata['model_config_sha256'] != hashlib.sha256((MODEL_DIR/'siglip2-base-patch16-224/config.json').read_bytes()).hexdigest():
        raise ValueError('Logo index/model mismatch; rebuild the index')
    with np.load(index, allow_pickle=False) as payload:
        refs=payload['embeddings']
    image=Image.open(io.BytesIO(blob))
    if image.width*image.height > 30000000:
        raise ValueError('Logo query pixel limit reached')
    image=rgb_image(image); w,h=image.size
    # Explicit proposals, not a trained detector. Capturing several regions
    # reduces whole-page dilution, while candidates remain non-blocking.
    boxes=[(0,0,w,h),(0,0,w,min(h,max(120,int(h*.3))))]
    if w>300:
        boxes += [(0,0,min(w,220),min(h,160)),(0,0,max(120,int(w*.4)),min(h,max(100,int(h*.4))))]
    if w>500 and h>300:
        boxes += [(0,0,w//2,h//3),(w//4,0,3*w//4,h//2),(w//2,0,w,h//3)]
    boxes=list(dict.fromkeys(boxes))
    crops=[image.crop(box) for box in boxes]
    for crop in crops: crop.thumbnail((768,768))
    similarities=embeddings(crops) @ refs.T
    scores={}
    for j,reference in enumerate(metadata['references']):
        crop_index=int(np.argmax(similarities[:,j])); value=float(similarities[crop_index,j])
        brand=reference['brand']
        if value > scores.get(brand,{}).get('cosine',-1):
            scores[brand]={'brand':brand,'cosine':round(value,5),'roi':list(boxes[crop_index]),'reference_sha256':reference['sha256']}
    ranked=sorted(scores.values(),key=lambda r:-r['cosine'])[:5]
    return {'model':'SigLIP2-local-image-references','brand_candidates':ranked,'top_margin':round(ranked[0]['cosine']-ranked[1]['cosine'],5) if len(ranked)>1 else None,'reference_count':len(refs),'gallery_brands':sorted({r['brand'] for r in metadata['references']}),'calibrated':False,'accepted_identity':None,'suspicious':False,'blocking':False,'note':'Это ближайшие картинки в ограниченной галерее, не распознанные бренды. Косинусное сходство не является вероятностью.'}
