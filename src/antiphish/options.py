"""Per-analysis component switches, isolated across requests and restored on exit."""
from contextvars import ContextVar

CURRENT = ContextVar('antiphish_components', default={})
FLAGS = ('ocr','qr','llm','siglip','logo_references','visual_brands','render_local','text_model','laya','hash_samples','url_iocs','reputation','templates','reviewed_samples','feed_phishing_database','feed_openphish','feed_phishtank')
BOUNDS = {'max_network_pages':(1,30), 'max_navigation_depth':(0,10), 'max_network_seconds':(5,180)}

def resolve(profile, overrides=None):
    if overrides is not None and not isinstance(overrides,dict):
        raise ValueError('Options must be an object')
    values = {name:True for name in FLAGS}
    values.update(ocr=profile!='fast',qr=profile!='fast',llm=profile=='deep',siglip=False,logo_references=False,visual_brands=profile!='fast')
    import os
    values['text_model']=profile=='deep' or bool(os.environ.get('ANTIPHISH_TEXT_MODEL_DIR'))
    values['laya']=profile=='deep' or bool(os.environ.get('ANTIPHISH_LAYA_MODEL_DIR'))
    values['render_local']=profile!='fast'
    for key,value in (overrides or {}).items():
        if key in FLAGS and type(value) is bool:
            values[key]=value
        elif key in BOUNDS and type(value) is int and BOUNDS[key][0]<=value<=BOUNDS[key][1]:
            values[key]=value
        else:
            raise ValueError('Invalid analysis option: '+str(key))
    return values

def enabled(name, default=True):
    return CURRENT.get().get(name,default)
