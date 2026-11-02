"""Fetch bounded passive images before a network-free document render.

Uses the same SSRF/TLS client as navigation, never a browser for image bytes.
Tracking pixels and token-bearing URLs are not requested. Failed images are
observations, not evidence of phishing or permission to substitute an exemplar.
"""
import base64
import io
import re
import time
from dataclasses import replace

from .urltools import normalize_url


def enrich_logos(extracted,report,fetch,limits,started):
    from PIL import Image
    from .utils import sha256_bytes
    remaining=limits.max_network_seconds-(time.monotonic()-started)
    if remaining<=.1:return
    asset_started=time.monotonic()
    spent=extracted.metadata.get('_image_asset_seconds',0.)
    deadline=asset_started+min(max(0.,8.-spent),remaining)
    attempts=extracted.metadata.get('_image_asset_attempts',0)
    cache=extracted.metadata.setdefault('_image_asset_cache',{})
    observations=[]
    candidates=[]
    for page in extracted.pages:
        for resource in page.resources:
            if resource.get('kind')!='img' or resource.get('tracking'):continue
            url=page.resource_urls.get(resource['url'],resource['url'])
            if '[redacted]' in url or '*' in url:continue
            target=normalize_url(url)
            if 'TOKENIZED_URL' in target.flags or 'ACTION_URL' in target.flags:continue
            candidates.append((not resource.get('identity_candidate'),page,resource,target))
    candidates.sort(key=lambda c:c[0])
    for _,page,resource,target in candidates:
        url=target.normalized
        if url not in cache:
            if attempts>=8 or time.monotonic()>=deadline:break
            attempts+=1
            entry={'url':target.redacted,'scope_id':page.id,'purpose':'passive-image'}
            try:
                budget=max(.1,deadline-time.monotonic())
                response=fetch(url,replace(limits,network_timeout_seconds=min(2.5,budget),
                    max_network_seconds=budget,max_http_bytes=min(limits.max_http_bytes,3*1024*1024)))
                if str(response.status)!='200':raise ValueError('Image HTTP '+str(response.status))
                media=response.content_type.split(';')[0].strip().lower()
                if media=='image/svg+xml':
                    from lxml import etree
                    if len(response.body)>2*1024*1024 or re.search(rb'<!DOCTYPE|<!ENTITY',response.body,re.I):raise ValueError('Unsafe SVG asset')
                    root=etree.fromstring(response.body,parser=etree.XMLParser(resolve_entities=False,no_network=True))
                    if etree.QName(root).localname!='svg':raise ValueError('Not SVG')
                    preview=None;status='FETCHED_VECTOR'
                else:
                    if not media.startswith('image/') and media!='application/octet-stream':raise ValueError('Not an image response')
                    with Image.open(io.BytesIO(response.body)) as source:
                        if source.width*source.height>30_000_000:raise ValueError('Image pixel limit')
                        if min(source.size)<=2:raise ValueError('Tracking-sized image')
                        source.load()
                        output=io.BytesIO();source.convert('RGBA').save(output,'PNG')
                    preview=output.getvalue();media='image/png';status='FETCHED'
                data=preview if preview else response.body
                encoded='data:'+media+';base64,'+base64.b64encode(data).decode('ascii')
                cache[url]=(encoded,preview,response.final_url)
                entry.update(status=status,sha256=sha256_bytes(data))
            except Exception as exc:
                cache[url]=None;entry.update(status='UNAVAILABLE',error=type(exc).__name__)
            observations.append(entry)
        asset=cache.get(url)
        if not asset:continue
        encoded,preview,final_url=asset
        page.render_assets[url]=encoded;page.render_assets[final_url]=encoded
        if resource.get('identity_candidate') and preview and not any(v.get('source_url')==target.redacted for v in page.visual_images):
            page.visual_images.append({'bytes':preview,'role':'logo-asset','source_url':target.redacted})
            if not page.image_bytes:
                page.image_bytes=preview;page.image_role='logo-asset';page.image_source_url=target.redacted
    if observations:
        old=report.configuration.get('visual_assets',{}).get('observations',[])
        report.configuration['visual_assets']={'attempts':attempts,'observations':old+observations,
            'limit':8,'budget_seconds':8,'svg_rendering':True,'tracking_pixels':False}
        report.network_activity.extend({**entry,'resource':True} for entry in observations)
    extracted.metadata['_image_asset_attempts']=attempts
    extracted.metadata['_image_asset_seconds']=spent+time.monotonic()-asset_started
