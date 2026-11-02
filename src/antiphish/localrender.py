"""Static visual rendering of mail/HTML/SVG. No JavaScript or external traffic."""
import re
import time
from functools import lru_cache


def safe_markup(markup,assets=None,base_url=None):
    from lxml import html,etree
    from urllib.parse import urljoin,unquote
    root=html.document_fromstring(markup[:1_000_000])
    declared_base=root.xpath('//base/@href')
    if declared_base:base_url=urljoin(base_url or '',declared_base[0])
    for node in root.xpath('//script|//iframe|//frame|//object|//embed|//link|//base|//meta|//audio|//video'):
        parent=node.getparent()
        if parent is not None:parent.remove(node)
    for node in root.xpath('//img'):
        small=any(re.match(r'^\s*[12](?:px)?\s*$',node.get(key,'') or '') for key in ('width','height'))
        tracker=re.search(r'(?i)(?:pixel|beacon|/mailstat/|/open/|/track(?:ing)?/)',node.get('src',''))
        if (small or tracker) and node.getparent() is not None:node.getparent().remove(node)
    for node in root.iter():
        if not isinstance(node.tag,str):continue
        for key in list(node.attrib):
            if key.lower().startswith('on') or key.lower() in {'srcdoc','formaction','action','srcset','autofocus','contenteditable'}:del node.attrib[key]
        if node.tag=='input':node.attrib.pop('value',None)
        if node.tag=='textarea':node.text=''
        for key in ('src','href','background'):
            value=node.get(key) or ''
            value=unquote(value) if value.lower().startswith('cid:') else value
            resolved=value if value in (assets or {}) else urljoin(base_url or '',value)
            if resolved in (assets or {}):node.set(key,assets[resolved])
        def replace_url(match):
            value=match.group(2);resolved=value if value in (assets or {}) else urljoin(base_url or '',value)
            return 'url("'+assets[resolved]+'")' if assets and resolved in assets else match.group(0)
        if node.get('style'):node.set('style',re.sub(r'''url\(\s*(['"]?)([^)'"\s]+)\1\s*\)''',replace_url,node.get('style')))
        if node.tag=='style' and node.text:node.text=re.sub(r'''url\(\s*(['"]?)([^)'"\s]+)\1\s*\)''',replace_url,node.text)
    head=root.find('head')
    if head is None:head=etree.SubElement(root,'head')
    csp=etree.Element('meta',{'http-equiv':'Content-Security-Policy','content':"default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:; script-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'"})
    head.insert(0,csp)
    style=etree.SubElement(head,'style');style.text='*{animation:none!important;transition:none!important}body{overflow-wrap:anywhere}img,svg{max-width:100%}'
    return html.tostring(root,encoding='unicode')


def visual_exclusions(page):
    return page.evaluate("""() => Array.from(document.querySelectorAll('button,footer,nav,article img,article svg,article h1,article h2,[class*="payment"],a')).filter(e => e.tagName!=='A' || /войти через|sign in with|continue with/i.test(e.textContent) || /accounts\\.google|login\\.microsoftonline|oauth/i.test(e.getAttribute('href')||'')).slice(0,60).map(e => {const r=e.getBoundingClientRect();return [r.x,r.y,r.x+r.width,r.y+r.height]}).filter(r=>r[2]>r[0]&&r[3]>r[1])""")


@lru_cache(maxsize=6)
def _render(markups):
    from playwright.sync_api import sync_playwright
    from .network import browser_executable,_BrowserDeadline
    result=[]
    with sync_playwright() as pw,_BrowserDeadline(pw,9):
        browser=pw.chromium.launch(executable_path=browser_executable(),headless=True,args=['--disable-extensions','--disable-sync','--disable-background-networking'])
        try:
            context=browser.new_context(java_script_enabled=False,service_workers='block',accept_downloads=False,
                                        viewport={'width':1100,'height':850},device_scale_factor=1)
            context.route('**/*',lambda route:route.abort())
            page=context.new_page();page.set_default_timeout(1800)
            for markup in markups:
                try:
                    page.set_content(markup,wait_until='domcontentloaded',timeout=1800)
                    page.evaluate('() => Promise.all(Array.from(document.images, i => i.decode().catch(() => null)))')
                    # Screenshot handles inline SVG and CSS. Limit document height
                    # to avoid attacker-controlled gigantic allocations.
                    height=min(2200,max(500,page.locator('body').bounding_box()['height']))
                    missing=page.evaluate('() => Array.from(document.images).filter(i=>!i.naturalWidth).length')
                    views=[{'bytes':page.screenshot(type='png',clip={'x':0,'y':0,'width':1100,'height':height},timeout=2200,animations='disabled'),'role':'local-render','excluded_regions':visual_exclusions(page),'missing_images':missing}]
                    nodes=page.locator('img,svg')
                    for index in range(min(nodes.count(),12)):
                        if len(views)>=4:break
                        node=nodes.nth(index);box=node.bounding_box()
                        if not box or box['y']>min(500,height*.35) or min(box['width'],box['height'])<16 or box['height']>450:continue
                        if node.evaluate("e=>!!e.closest('button,footer,nav,article') || (e.tagName==='IMG' && !e.naturalWidth)"):continue
                        if box['x']<0 or box['x']+box['width']>1100:continue
                        views.append({'bytes':page.screenshot(type='png',clip=box,timeout=1200,animations='disabled'),'role':'logo-crop','crop_box':box})
                    result.append(views)
                except Exception:result.append([])
            context.close()
        finally:browser.close()
    return tuple(result)


def enrich(extracted,report):
    candidates=[p for p in extracted.pages if p.source_html and not p.screenshot_sha256]
    if not candidates:return
    # Prioritize the mail body and credential pages, then HTML attachments.
    # A published sheet wrapper contains only a title and JS. Its actual sheet
    # must receive the render slot, rather than three earlier empty wrappers.
    deferred={u.scope_id for u in extracted.urls if u.source=='hosted-document'}
    routes={r.get('to'):r.get('depth',0) for r in report.routes}
    def rank(p):
        body=p.id in extracted.metadata.get('message_scopes',set())
        secret=any(set(f.sensitive_types)&{'password','otp','card','wallet_secret'} for f in p.forms)
        return (not body,not secret,p.id in deferred,not bool(p.render_assets),-routes.get(p.id,0),-min(len(p.text),1200))
    candidates=sorted(candidates,key=rank)
    useful=[p for p in candidates if p.id not in deferred]
    candidates=(useful or candidates)[:4]
    assets=extracted.metadata.get('cid_images',{})
    prepared=[];selected=[];preparation_errors=[]
    for page in candidates:
        try:prepared.append(safe_markup(page.source_html,{**assets,**page.render_assets},page.url));selected.append(page)
        except Exception as exc:preparation_errors.append(type(exc).__name__)
    if not prepared:
        report.configuration['local_render']={'status':'FAILED','requested':len(candidates),'rendered':0,'errors':preparation_errors}
        report.model_warnings.append('Не удалось подготовить локальный рендер')
        return
    started=time.perf_counter()
    try:
        images=_render(tuple(prepared))
        for page,views in zip(selected,images):
            for view in views:
                if view['role']=='local-render' and page.id in extracted.metadata.get('message_scopes',set()):view={**view,'role':'mail-render'}
                page.visual_images.append(view)
        report.configuration['local_render']={'requested':len(selected),'rendered':sum(bool(x) for x in images),
            'javascript':False,'network':False,'missing_images':sum(v.get('missing_images',0) for vs in images for v in vs),'seconds':round(time.perf_counter()-started,3)}
        if not all(images):report.model_warnings.append('Часть локальных изображений не отрисована')
    except Exception as exc:
        report.configuration['local_render']={'status':'UNAVAILABLE','error':type(exc).__name__,'network':False,'javascript':False}
        report.model_warnings.append('Локальная отрисовка недоступна: '+type(exc).__name__)
