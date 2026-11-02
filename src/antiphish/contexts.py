"""Bounded, source-linked evidence. Untrusted markup is always displayed as text."""
from __future__ import annotations

import hashlib
import re

from .models import AnalysisReport

from .policy import BLOCKING_CODES as PROOFS
ALERTS = {
    'SECRET_REPLY_REQUEST','CLICKFIX_EXECUTION','UPFRONT_PAYOUT_FEE','SAFE_ACCOUNT_TRANSFER','REMOTE_BANK_CONTROL','SECRET_TO_PUBLIC_FORM','FAKE_BROWSER_ADDRESS',
    'UNVERIFIED_TRANSFER_LURE', 'DOCUMENT_IDENTITY_HOSTING_MISMATCH', 'ACCOUNT_RECOVERY_ON_USER_HOSTING',
    'ACTIVE_PAYLOAD_BEHAVIOR', 'BRAND_FORM_IMPERSONATION', 'UNVERIFIED_AUTH_COLLECTOR', 'REPUTATION_URL_MATCH',
    'CAMPAIGN_TEMPLATE_MATCH', 'DANGEROUS_ATTACHMENT', 'OFFICE_MACRO', 'UNVERIFIED_REWARD_LURE',
    'UNVERIFIED_INVESTMENT_LURE', 'UNVERIFIED_ACCOUNT_LURE', 'SECURITY_THREAT_TO_MESSENGER', 'REPLY_FOR_REWARD',
    'VISUAL_REWARD_LURE', 'MAILBOX_REVIEW_LURE', 'FAKE_DOCUMENT_VIEWER', 'CREDENTIAL_LURE',
    'MAILBOX_LOGIN_IN_CMS_ASSET', 'REVIEWED_MESSAGE_SIMILARITY', 'VISUAL_BRAND_AUTH_MISMATCH',
}


def redact(value: str, limit: int = 2400) -> str:
    value = str(value or '')[:max(limit * 3, 8000)]
    value = re.sub(r'(?i)(/bot)\d+:[\w-]+', r'\1[REDACTED]', value)
    value = re.sub(r'(?i)([?&](?:token|access_token|auth|password|pass|pwd|otp|code|key|secret|session|email)=)[^&\s<>"\']+', r'\1[REDACTED]', value)
    value = re.sub(r'(?i)(\b(?:password|passwd|api_key|access_token|secret)\s*[:=]\s*["\'])[^"\']*', r'\1[REDACTED]', value)
    return value[:limit]


def form_markup(page, form, root=None) -> str:
    """Retain structure and recipients, remove values, never execute scripts."""
    if not page.source_html or not form.selector:
        return form.safe_structure or ''
    try:
        from lxml import html, etree
        if root is None:
            root = html.fromstring(page.source_html, parser=html.HTMLParser(no_network=True))
        nodes = root.getroottree().xpath(form.selector)
        if not nodes:
            return form.safe_structure or ''
        node = nodes[0]
        for field in node.xpath('.//input|.//textarea|.//option'):
            if 'value' in field.attrib:
                field.set('value', '[REDACTED]')
            if field.tag == 'textarea':
                field.text = '[REDACTED]'
        return redact(etree.tostring(node, encoding='unicode', method='html'), 3500)
    except Exception:
        return form.safe_structure or ''


def focused_text(text, matches, radius=100):
    windows=[]
    for item in matches:
        needle=item.get('text','')
        position=text.casefold().find(needle.casefold()) if needle else -1
        if position>=0:
            windows.append((max(0,position-radius),min(len(text),position+len(needle)+radius)))
    merged=[]
    for start,end in sorted(windows):
        if merged and start<=merged[-1][1]:
            merged[-1]=(merged[-1][0],max(end,merged[-1][1]))
        else:
            merged.append((start,end))
    return '\n…\n'.join(('…' if a else '')+text[a:b]+('…' if b<len(text) else '') for a,b in merged)[:2200]


def attach_context(report: AnalysisReport, extracted) -> None:
    pages = {page.id: page for page in report.pages}
    markup_roots, form_contexts = {}, {}
    message_text = extracted.metadata.get('message_text', extracted.text)
    headers = extracted.metadata.get('headers', {})
    report.message = {key: headers.get(key, '') for key in ('from', 'to', 'subject', 'reply-to')}
    report.message['text_excerpt'] = redact(message_text, 12000)
    report.message['text_truncated'] = len(message_text)>12000
    report.message['text_length'] = len(message_text)
    report.learning_message = message_text
    from .reviews import message_signature
    report.learning_signature = message_signature(message_text, headers.get('subject',''), [b.brand for b in report.brands])
    report.learning_pages = []
    for page in report.pages:
        from .templates import signature
        fp = report.fingerprints
        for item in fp.get('network_pages', []):
            if item.get('url') == page.url:
                fp = item.get('fingerprints', {})
                break
        # Local MIME HTML has a separate fingerprint per part.
        for item in fp.get('html_parts', []):
            if item.get('sha256') == page.sha256:
                fp = item
                break
        dom, text, types = signature(page, fp)
        report.learning_pages.append({'id': page.id, 'sha256': page.sha256, 'url': page.url,
            'dom': dom, 'text': text, 'types': types, 'identity_source': page.identity_source,
            'has_forms': bool(page.forms), 'title': page.title,'text_body':page.text[:120000]})
    for index, evidence in enumerate(report.reason_codes):
        details = evidence.details
        page = pages.get(evidence.scope_id)
        decision=report.configuration.get('decision')
        decisive=bool(decision and any(r['code']==evidence.code and r['scope_id']==evidence.scope_id for r in decision['reasons']))
        role=('proof' if evidence.code in PROOFS else 'alert') if decisive else 'observation'
        if decision is None:
            role='proof' if evidence.code in PROOFS else 'alert' if evidence.code in ALERTS and report.verdict.value!='NOT_DETECTED' else 'observation'
        context = {'id': f'evidence-{index}', 'scope_id': evidence.scope_id,
            'policy_role': role, 'affects_verdict':decisive,
            'source': evidence.source or ('page' if page else 'message'),
            'selection': 'page-context' if page else 'object-context'}
        if page:
            context.update(source_url=page.url, source_sha256=page.sha256, title=page.title,
                text_excerpt=redact(page.text, 1800))
            form_id = details.get('form_id')
            form_index = details.get('form_index')
            forms = [f for f in page.forms if f.id == form_id] if form_id else page.forms[form_index:form_index+1] if isinstance(form_index, int) else []
            if forms:
                form = forms[0]
                if page.id not in markup_roots:
                    try:
                        from lxml import html
                        markup_roots[page.id] = html.fromstring(page.source_html,parser=html.HTMLParser(no_network=True)) if page.source_html else None
                    except Exception:
                        markup_roots[page.id] = None
                key = (page.id,form.id)
                if key not in form_contexts:
                    form_contexts[key] = form_markup(page,form,markup_roots[page.id])
                context.update(kind='form', selection='exact-form', selector=form.selector,
                    destination=redact(form.destination), sensitive_types=form.sensitive_types,
                    code_excerpt=form_contexts[key], fields=form.fields)
            elif evidence.code in {'SCRIPT_EXFILTRATION', 'SECRET_TO_MESSAGING_API', 'OBFUSCATED_LURE_SCRIPT', 'HIDDEN_REDIRECT'} and page.source_html:
                context.update(kind='code', code_excerpt=redact(page.source_html, 2200))
            if page.image_bytes:
                context['image_artifact'] = hashlib.sha256(page.image_bytes).hexdigest()
                context['image_label'] = 'Логотип со страницы' if page.image_role in {'logo-asset','embedded-logo'} else 'Снимок страницы' if page.identity_source == 'dom' else 'Изображение источника' if page.identity_source=='image' else 'Изображение, переданное в OCR'
        else:
            context.update(kind='message', source_sha256=report.input.get('sha256'),
                text_excerpt=redact(message_text, 1800))
        if evidence.code in {'KNOWN_BAD_URL', 'REPUTATION_URL_MATCH', 'IOC_SHA256_MATCH', 'KNOWN_SAMPLE_MATCH', 'REVIEWED_PHISHING_SAMPLE', 'REVIEWED_BENIGN_SAMPLE'}:
            context.update(kind='indicator', selection='exact-indicator', indicator=details.get('url') or details.get('sha256'), provenance=details.get('sources') or details.get('source'))
        attachment_hash = details.get('attachment_sha256') or (page.sha256 if page else None)
        attachment = next((a for a in report.attachments if a.sha256 == attachment_hash),None)
        if attachment or 'attachment' in details:
            context['attachment'] = attachment.name if attachment else details['attachment']
            context['attachment_sha256'] = attachment.sha256 if attachment else details.get('attachment_sha256')
            if not page and context['attachment_sha256']:
                context['source_sha256'] = context['attachment_sha256']
        if evidence.code in {'PDF_ACTIVE_CONTENT','ACTIVE_PAYLOAD_BEHAVIOR','OFFICE_MACRO'}:
            fingerprints = report.fingerprints
            if details.get('attachment'):
                fingerprints = next((a['fingerprints'] for a in fingerprints.get('attachment_fingerprints',[]) if a['sha256']==details.get('attachment_sha256')),fingerprints)
            actions = details.get('objects') or fingerprints.get('pdf_actions',[])
            snippets = [a.get('script',{}).get('code_excerpt','') for a in actions]
            modules = fingerprints.get('vba_modules',[])
            snippets += [m.get('code_excerpt','') for m in modules]
            context.update(kind='document',selection='document-actions',document_page=details.get('page'),
                code_excerpt=redact('\n\n'.join(x for x in snippets if x),3000),actions=actions[:10],modules=modules[:10])
        if evidence.code == 'QR_EXTERNAL_DESTINATION':
            context.update(kind='qr',indicator=details.get('destination'),selection='decoded-qr')
        if details.get('matched_text'):
            context['matched_text'] = redact(details['matched_text'], 300)
            context['selection'] = 'exact-text'
        matches=details.get('trigger_matches',[]) or ([{'text':details['matched_text']}] if details.get('matched_text') else [])
        if matches:
            selected=focused_text(page.text if page else message_text,matches)
            if selected:
                context.update(text_excerpt=redact(selected,2400),highlights=matches,selection='exact-text')
        context['explanation']=details.get('explanation')
        if details.get('matched_code'):
            context.update(code_excerpt=redact(details['matched_code'],1800),code_selection='matched-script')
        header_names={'FROM_REPLYTO_MISMATCH':['from','reply-to'],'FROM_RETURNPATH_MISMATCH':['from','return-path'],'AUTHENTICATION_FAILURE':['authentication-results']}.get(evidence.code)
        if header_names:
            source_headers=details.get('header_context') or headers
            context.update(kind='headers',selection='exact-headers',source_sha256=details.get('source_sha256',context.get('source_sha256')),text_excerpt='\n'.join(key+': '+source_headers.get(key,'') for key in header_names),text_truncated=False,
                highlights=[{'text':str(details[key])} for key in ('from_domain','reply_to_domain','return_path_domain') if details.get(key)])
        context['destinations']=details.get('destinations',[])
        context['text_truncated']=context.get('selection') not in {'exact-text','exact-headers'} and len(page.text if page else message_text)>1800
        context['routes'] = [r for r in report.routes if r.get('to') == (page.id if page else details.get('url'))][:5]
        evidence.context = context
        if details.get('ai_based'):
            evidence.context.update(ai_based=True,selection='model-input',text_excerpt=redact(details.get('model_excerpt',''),1600))
        if details.get('image_artifact'):
            evidence.context.update(image_artifact=details['image_artifact'],image_label='Изображение с найденным брендом')
