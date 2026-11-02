"""Local logo localization with verifiable image features, without neural weights.

Only exact reference pixels or geometrically consistent SIFT correspondences
produce candidates. A nearest neighbour is never forced for an unknown image.
Logo presence describes a picture; it does not establish page/account identity.
"""
from __future__ import annotations

import hashlib
import io
import json
import time
from functools import lru_cache
from pathlib import Path

from .config import RESOURCE_DIR


def _image(blob):
    import numpy as np
    from PIL import Image
    with Image.open(io.BytesIO(blob)) as source:
        if source.width*source.height>30_000_000:
            raise ValueError('Visual pixel limit reached')
        image=source.convert('RGBA')
        background=Image.new('RGBA',image.size,'white')
        background.alpha_composite(image)
        image=background.convert('RGB')
    return image,np.asarray(image)


def _pixel_hash(image):
    return hashlib.sha256(str(image.size).encode()+image.tobytes()).hexdigest()


def _shape(array):
    """Trim a uniform border, retain colour, shape and aspect ratio."""
    import cv2
    import numpy as np
    corners=np.float32([array[0,0],array[0,-1],array[-1,0],array[-1,-1]])
    background=np.median(corners,axis=0)
    mask=np.max(np.abs(array.astype('float32')-background),axis=2)>35
    yy,xx=np.where(mask)
    if len(xx)<20:return None
    left,right,top,bottom=int(xx.min()),int(xx.max())+1,int(yy.min()),int(yy.max())+1
    if min(right-left,bottom-top)<6:return None
    cropped=array[top:bottom,left:right]
    small=cv2.resize(cropped,(48,48),interpolation=cv2.INTER_AREA).astype('float32')/255
    gray=cv2.cvtColor(small,cv2.COLOR_RGB2GRAY)
    if gray.std()<.06:return None
    vector=(gray-gray.mean()).ravel();vector/=max(float(np.linalg.norm(vector)),1e-9)
    foreground=cv2.resize(mask[top:bottom,left:right].astype('uint8'),(48,48),interpolation=cv2.INTER_NEAREST)>0
    return small,vector,(right-left)/(bottom-top),foreground


def _proposals(array):
    import cv2
    import numpy as np
    gray=cv2.cvtColor(array,cv2.COLOR_RGB2GRAY)
    # White/light screenshot backgrounds: components locate actual image
    # content. Other backgrounds still have the SIFT path; do not force a crop.
    mask=np.uint8(gray<220)*255
    rows=set()
    h,w=gray.shape
    # Group separated letters and symbol + wordmark. A component per letter
    # cannot match the full logo. Edge masks also work on coloured headers.
    edge=cv2.Canny(gray,60,160)
    hsv=cv2.cvtColor(array,cv2.COLOR_RGB2HSV)
    colour=np.uint8((hsv[:,:,1]>65)&(hsv[:,:,2]>65))*255
    for source in (colour,mask,edge):
        for kx,ky in ((1,1),(5,3),(11,3)):
            joined=cv2.dilate(source,np.ones((ky,kx),np.uint8))
            _,_,stats,_=cv2.connectedComponentsWithStats(joined,8)
            for x,y,bw,bh,area in stats[1:]:
                if area<40 or min(bw,bh)<8 or not .12<bw/bh<14 or bw*bh>=w*h*.45:continue
                # Undo dilation's padding. Otherwise the first letter beside
                # a symbol contaminates its crop (e.g. the A beside Avito).
                yy,xx=np.where(source[y:y+bh,x:x+bw]>0)
                if len(xx):rows.add((int(x+xx.min()),int(y+yy.min()),int(x+xx.max()+1),int(y+yy.max()+1)))
    return sorted(rows,key=lambda r:(r[1]>h*.4,-(r[2]-r[0])*(r[3]-r[1])))[:90]


@lru_cache(maxsize=2)
def _references(root_string, manifest_mtime):
    import cv2
    import numpy as np
    root=Path(root_string)
    manifest=root/'manifest.jsonl'
    from .brands import load_brands
    from .policy import official_host
    from .urltools import normalize_url
    brands={b['name']:b for b in load_brands()}
    detector=cv2.SIFT_create(nfeatures=250,contrastThreshold=.02)
    records=[]
    from .logogallery import reviewed_references
    for row in reviewed_references(root):
        path=Path(row['_file'])
        image,array=_image(path.read_bytes())
        if min(image.size)<8:continue
        gray=cv2.cvtColor(array,cv2.COLOR_RGB2GRAY)
        # Upsampling a small favicon helps localization but creates no new
        # evidence: geometric inliers and uniqueness are still required.
        factor=192/max(image.size)
        gray=cv2.resize(gray,None,fx=factor,fy=factor,interpolation=cv2.INTER_CUBIC)
        points,desc=detector.detectAndCompute(gray,None)
        if float(gray.std())<15:continue
        records.append({**row,'pixel_sha256':_pixel_hash(image),'reference_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                        'points':np.float32([p.pt for p in points]),'descriptors':desc,'shape':gray.shape,'appearance':_shape(array)})
    return records


@lru_cache(maxsize=2)
def _feature_index(signature):
    import cv2
    import numpy as np
    records=[r for root,mtime in signature for r in _references(root,mtime)]
    arrays=[];owners=[]
    for r in records:
        if r['descriptors'] is not None and len(r['descriptors'])>=8:
            arrays.append(r['descriptors']);owners.extend([r['reference_sha256']]*len(r['descriptors']))
    if not arrays:return None,[]
    matcher=cv2.FlannBasedMatcher(dict(algorithm=1,trees=4),dict(checks=48))
    matcher.add([np.vstack(arrays)]);matcher.train()
    return matcher,owners


def match_image(blob: bytes, *, gallery: Path | None=None, budget_seconds=2.0) -> dict:
    import cv2
    import numpy as np
    started=time.perf_counter()
    from .logogallery import roots
    records=[];signature=[]
    for root in roots(gallery):
        manifest=root/'manifest.jsonl'
        if manifest.is_file():
            key=(str(root.resolve()),manifest.stat().st_mtime_ns);signature.append(key)
            records.extend(_references(*key))
    # A shared/generic image cannot identify either of its alleged brands.
    identities={}
    for r in records:identities.setdefault(r['pixel_sha256'],set()).add(r['brand'])
    records=list({(r['brand'],r['pixel_sha256']):r for r in records if len(identities[r['pixel_sha256']])==1}.values())
    image,array=_image(blob)
    original_size=image.size
    image.thumbnail((1600,2200))
    query=cv2.cvtColor(np.asarray(image),cv2.COLOR_RGB2GRAY)
    detector=cv2.SIFT_create(nfeatures=1400,contrastThreshold=.02)
    points,desc=detector.detectAndCompute(query,None)
    query_points=np.float32([p.pt for p in points])
    pixel_hash=_pixel_hash(image) if image.size==original_size else _pixel_hash(_image(blob)[0])
    exact=[r for r in records if r['pixel_sha256']==pixel_hash]
    candidates=[];limited=False
    if len({r['brand'] for r in exact})==1:
        r=exact[0]
        candidates.append({'brand':r['brand'],'method':'exact-reference-pixels','inliers':None,'roi':[0,0,*original_size],
                           'reference_sha256':r['reference_sha256']})
    if not candidates:
        resized=np.asarray(image)
        for x1,y1,x2,y2 in _proposals(resized):
            shape=_shape(resized[y1:y2,x1:x2])
            if shape is None:continue
            rgb,vector,aspect,foreground=shape
            matches=[]
            for r in records:
                ref=r['appearance']
                if ref is None or not .8<aspect/ref[2]<1.25:continue
                correlation=float(vector@ref[1]);error=float(np.abs(rgb-ref[0]).mean())
                overlap=float(np.logical_and(foreground,ref[3]).sum()/max(1,np.logical_or(foreground,ref[3]).sum()))
                # A small raster icon changes under scaling/anti-aliasing.
                # Verify silhouette and spatial colour together, not OCR or
                # the similarity of the entire page to a reference picture.
                if (correlation>=.975 and error<=.045) or (correlation>=.94 and error<=.05 and overlap>=.85):
                    matches.append((correlation-error,r,correlation,error,overlap))
            matches.sort(key=lambda x:-x[0])
            if not matches or (len(matches)>1 and matches[0][1]['brand']!=matches[1][1]['brand'] and matches[0][0]-matches[1][0]<.04):continue
            _,r,corr,error,overlap=matches[0]
            sx,sy=original_size[0]/image.width,original_size[1]/image.height
            candidates.append({'brand':r['brand'],'method':'localized-pixel-shape','inliers':None,
                               'shape_correlation':round(corr,5),'colour_error':round(error,5),
                               'silhouette_iou':round(overlap,5),
                               'roi':[round(x1*sx),round(y1*sy),round(x2*sx),round(y2*sy)],'reference_sha256':r['reference_sha256']})
    matcher=cv2.BFMatcher(cv2.NORM_L2)
    matching_started=time.perf_counter()
    geometric_records=records
    if len(records)>100 and desc is not None:
        # A global local-feature index proposes references. Each proposal
        # still needs the original ratio test and full RANSAC verification.
        # This avoids a growing gallery silently exhausting its time budget
        # before reaching brands near the end of the manifest.
        from collections import Counter
        index,owners=_feature_index(tuple(signature))
        if index is not None:
            votes=Counter()
            for pair in index.knnMatch(desc,k=4):
                for digest in {owners[m.trainIdx] for m in pair if m.distance<260}:votes[digest]+=1
            shortlist={key for key,count in votes.most_common(24) if count>=3}
            geometric_records=sorted((r for r in records if r['reference_sha256'] in shortlist),key=lambda r:-votes[r['reference_sha256']])
    if desc is not None and len(desc)>=8:
        for r in geometric_records:
            if time.perf_counter()-matching_started>budget_seconds:
                limited=True;break
            ref=r['descriptors']
            if ref is None or len(ref)<8:continue
            pairs=matcher.knnMatch(ref,desc,k=2)
            good=[a for pair in pairs if len(pair)==2 for a,b in [pair] if a.distance<.65*b.distance]
            # One destination feature cannot support several independent matches.
            good=list({m.trainIdx:m for m in sorted(good,key=lambda m:-m.distance)}.values())
            if len(good)<8:continue
            src=np.float32([r['points'][m.queryIdx] for m in good])
            dst=np.float32([query_points[m.trainIdx] for m in good])
            transform,mask=cv2.findHomography(src,dst,cv2.RANSAC,3.0)
            if transform is None or mask is None or not np.isfinite(transform).all():continue
            selected=mask.ravel().astype(bool);inliers=int(selected.sum())
            if inliers<8 or inliers/len(good)<.7:continue
            h,w=r['shape']
            # Reject degenerate matches to one edge, tiny spot or repeated text.
            coverage=cv2.contourArea(cv2.convexHull(src[selected]))/(h*w)
            if coverage<.12:continue
            polygon=cv2.perspectiveTransform(np.float32([[0,0],[w,0],[w,h],[0,h]]).reshape(1,4,2),transform)[0]
            if not np.isfinite(polygon).all() or not cv2.isContourConvex(polygon):continue
            area=abs(cv2.contourArea(polygon))
            if area<100 or area>query.size*.65:continue
            x,y,bw,bh=cv2.boundingRect(polygon)
            if min(bw,bh)<8 or max(bw,bh)/min(bw,bh)>12 or x< -3 or y< -3 or x+bw>image.width+3 or y+bh>image.height+3:continue
            sx,sy=original_size[0]/image.width,original_size[1]/image.height
            candidates.append({'brand':r['brand'],'method':'sift-ransac','inliers':inliers,
                               'inlier_fraction':round(inliers/len(good),4),'reference_coverage':round(coverage,4),
                               'roi':[round(x*sx),round(y*sy),round((x+bw)*sx),round((y+bh)*sy)],
                               'reference_sha256':r['reference_sha256']})
    unique={}
    for candidate in sorted(candidates,key=lambda x:-(x.get('inliers') or 10000)):
        unique.setdefault(candidate['brand'],candidate)
    candidates=list(unique.values())[:5]
    return {'model':'Local-logo-geometry','status':'LIMITED' if limited else 'COMPLETE',
            'brand_candidates':candidates,'accepted_identity':None,'reference_count':len(records),
            'image_size':list(original_size),
            'geometric_references_checked':len(geometric_records),
            'suspicious':False,'blocking':False,'calibrated':False,
            'note':'Совпадение изображения логотипа; само по себе не устанавливает владельца сайта.',
            'runtime_ms':round((time.perf_counter()-started)*1000,2)}
