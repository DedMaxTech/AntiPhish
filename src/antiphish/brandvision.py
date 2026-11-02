"""Localized OCR wordmarks complement image references without inventing a form."""
import io
import re
from PIL import Image

from .policy import catalog,PAYMENT_NETWORKS
from .texttools import normalize_russian


def wordmarks(lines,size,*,logo_asset=False):
    result=[];seen=set()
    for line in lines:
        box=line.get('roi');text=normalize_russian(line.get('text','')).casefold().strip()
        if not box or len(box)!=4 or line.get('score',0)<.9 or not size[1]:continue
        if not logo_asset and box[1]>size[1]*.30:continue
        if len(text)>65 or len(text.split())>5:continue
        if re.search(r'(?i)pay|оплат|плат[её]ж|accepted',text):continue
        # Short header labels only. A paragraph mentioning a bank is not its logo.
        for brand,patterns in catalog():
            if brand['name'].casefold() in PAYMENT_NETWORKS or brand['name'] in seen:continue
            if any(p.search(text) for p in patterns):
                longest=max((len(a) for a in brand['aliases'] if a.casefold() in text),default=0)
                remainder=re.sub(r'(?i)личный кабинет|вход|онлайн|online|account|login|sign in|войти','',text)
                if len(re.sub(r'\W','',remainder))>longest+4:continue
                seen.add(brand['name'])
                result.append({'brand':brand['name'],'method':'ocr-header-wordmark','ocr_score':line['score'],
                               'text':line['text'],'roi':box,'blocking':False})
    return result[:5]


def enrich_wordmarks(visual,blob,*,image_role=None):
    from .ocr import recognize_layout
    with Image.open(io.BytesIO(blob)) as source:
        if source.width*source.height>30_000_000:return
        asset=image_role in {'logo-asset','embedded-logo','logo-crop'}
        # Keep a long screenshot's header at readable resolution instead of
        # shrinking its small wordmark with the entire page. Coordinates stay
        # relative to the original image because the crop begins at (0, 0).
        region=source if asset or source.height<=600 else source.crop((0,0,source.width,min(source.height,max(40,min(600,round(source.height*.30))))))
        layout=recognize_layout(region)
    existing={c['brand'] for c in visual.get('brand_candidates',[])}
    found=wordmarks(layout['lines'],visual['image_size'],logo_asset=image_role in {'logo-asset','embedded-logo','logo-crop'})
    visual['ocr_status']=layout['status']
    visual['ocr_region']=[0,0,region.width,region.height]
    visual['ocr_wordmarks']=found
    visual['ocr_lines']=layout.get('lines',[])
    visual['ocr_text']='\n'.join(line.get('text','') for line in layout.get('lines',[]))[:6000]
    visual['brand_candidates'].extend(c for c in found if c['brand'] not in existing)
