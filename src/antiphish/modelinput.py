"""Model source text and grounded quotations, without duplicated MIME bodies."""
import re


def message_text(extracted,report):
    text=extracted.metadata.get('message_text',extracted.text)
    if extracted.kind!='eml':return text
    scopes=extracted.metadata.get('message_scopes',set())
    rendered=[m for m in report.model_evidence if m.get('image_context',{}).get('scope_id') in scopes and m.get('image_context',{}).get('image_role')=='mail-render' and m.get('ocr_text')]
    for item in rendered[:2]:
        ocr=item['ocr_text'];a=set(re.findall(r'\w+',text.casefold()));b=set(re.findall(r'\w+',ocr.casefold()))
        if b and (not text.strip() or len(b-a)/len(b)>.3):text+='\n\nТекст на изображении письма:\n'+ocr
    return text.strip()


def sources(extracted,report):
    result=[]
    if extracted.kind=='eml':
        headers=extracted.metadata.get('headers',{})
        text='\n'.join(k+': '+str(headers[k])[:350] for k in ('subject','from','reply-to') if headers.get(k))
        if text:result.append({'id':'message-headers','label':'Заголовки письма','text':text})
    body=message_text(extracted,report)
    if body:result.append({'id':'message' if extracted.kind=='eml' else 'input','label':'Письмо' if extracted.kind=='eml' else 'Исходный документ','text':body[:4500]})
    own=extracted.metadata.get('message_scopes',set())
    candidates=[p for p in report.pages if p.id not in own and p.text]
    for p in sorted(candidates,key=lambda p:(not bool(p.forms),-len(p.text)))[:2 if body else 3]:
        remaining=7500-sum(len(s['text']) for s in result)
        if remaining<=0:break
        result.append({'id':p.id,'label':(p.url or p.title or 'Документ')[:240],'text':p.text[:min(2100,remaining)]})
    return result


def links(report):
    from .urltools import auxiliary_link,unwrap_url
    result=[];seen=set()
    for u in sorted(report.urls,key=lambda x:x.navigation_role!='action'):
        if u.source not in {'html:a:href','link-wrapper','hosted-document','javascript-navigation','text'} or auxiliary_link(u):continue
        target=u.navigation_url or u.normalized or u.original
        for _ in range(4):
            inner=unwrap_url(target)
            if not inner or inner==target:break
            target=inner
        if target in seen:continue
        seen.add(target)
        result.append({'scope':u.scope_id,'label':(u.displayed_text or '')[:90],'target':target[:260],'status':u.fetch_status})
        if len(result)>=6:break
    return result


def ground_quotes(quotes,source_texts):
    """Keep original characters and offsets. Ignore generated or invented text."""
    result=[]
    for quote in quotes[:6]:
        if not isinstance(quote,str) or not quote.strip():continue
        for source in source_texts:
            text=source['text'];start=text.find(quote)
            if start<0:
                parts=re.split(r'\s+',quote.strip())
                if len(quote)>400:continue
                match=re.search(r'\s+'.join(re.escape(p) for p in parts),text)
                if not match:continue
                start=match.start();quote=match.group()
            result.append({'text':quote,'source_id':source['id'],'source_label':source['label'],'start':start,'end':start+len(quote)})
            break
    return result
