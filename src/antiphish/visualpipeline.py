"""Inspect individual assets and renders, retaining every owning document scope."""
import copy
import hashlib
from collections import deque


def inspect(pages,*,ocr=True,limit=6):
    from .visual import match_image
    from .brandvision import enrich_wordmarks
    queues={key:deque() for key in ('render','image','crop')};all_views=[]
    def page_priority(page):
        render=any(v['role']=='mail-render' for v in page.visual_images)
        secret=any(set(f.sensitive_types)&{'password','otp','card','wallet_secret'} for f in page.forms)
        return (not secret,not render,not bool(page.render_assets),not bool(page.forms),-min(len(page.text),2000))
    for page in sorted(pages,key=page_priority):
        views=list(page.visual_images)
        if page.image_bytes:views.append({'bytes':page.image_bytes,'role':page.image_role or ('screenshot' if page.screenshot_sha256 else 'source-image'),'excluded_regions':page.visual_exclusions})
        for view in views:
            digest=hashlib.sha256(view['bytes']).hexdigest()
            entry=(page,view,digest);all_views.append(entry)
            category='crop' if view['role']=='logo-crop' else 'render' if view['role'] in {'mail-render','local-render','pdf-render','screenshot'} else 'image'
            queues[category].append(entry)
    selected={};warnings=[]
    while any(queues.values()) and len(selected)<limit:
        for queue in queues.values():
            if not queue or len(selected)>=limit:continue
            page,view,digest=queue.popleft()
            selected.setdefault(digest,(page,view))
    results={}
    for digest,(page,view) in selected.items():
        try:
            result=match_image(view['bytes'])
            if ocr:enrich_wordmarks(result,view['bytes'],image_role=view['role'])
            results[digest]=result
        except Exception as exc:warnings.append('Распознавание изображения: '+type(exc).__name__)
    evidence=[];seen=set()
    for page,view,digest in all_views:
        key=(page.id,digest)
        if digest not in results or key in seen:continue
        if len(evidence)>=18:break
        seen.add(key);result=copy.deepcopy(results[digest])
        excluded=view.get('excluded_regions',[])
        def relevant(candidate):
            box=candidate.get('roi',[])
            if len(box)!=4:return True
            x,y=(box[0]+box[2])/2,(box[1]+box[3])/2
            return not any(x1<=x<=x2 and y1<=y<=y2 for x1,y1,x2,y2 in excluded)
        result['brand_candidates']=[c for c in result.get('brand_candidates',[]) if relevant(c)]
        if 'ocr_wordmarks' in result:result['ocr_wordmarks']=[c for c in result['ocr_wordmarks'] if relevant(c)]
        result['image_context']={'scope_id':page.id,'url':page.url,'title':page.title,'artifact_id':digest,
            'image_source_url':view.get('source_url',page.image_source_url if view['role'] in {'logo-asset','embedded-logo','source-image'} else None),'image_role':view['role'],'crop_box':view.get('crop_box')}
        result['graphic_matches']=[c for c in result['brand_candidates'] if not c.get('method','').startswith('ocr-')]
        result['text_matches']=[c for c in result.get('ocr_wordmarks',[]) if relevant(c)]
        if view.get('missing_images'):result['missing_images']=view['missing_images']
        evidence.append(result)
    return evidence,warnings
