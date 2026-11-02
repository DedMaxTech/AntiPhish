"""Combine semantic model votes into an explicitly AI-based review warning."""
import re

from .models import Evidence,Severity


def annotate(report):
    votes=[]
    for result in report.model_evidence:
        name=result.get('model','');scores=result.get('scores',{})
        if name=='Laya multilingual' and result.get('status')=='COMPLETE':
            strength=min(scores.get('phishing',0),result.get('fraud_score',0))
            if strength>=.9:votes.append({'family':'laya','model':name,'score':strength,'excerpt':result.get('evidence_text','')})
        elif 'phishing-scam-detector' in name and scores.get('fraud',0)>=.9:
            votes.append({'family':'horizon','model':name,'score':scores['fraud'],'excerpt':result.get('evidence_text','')})
        elif result.get('suspicious') and result.get('parse_status')=='OK' and not result.get('validation_notes'):
            facts=result.get('structured_extract') or {}
            if facts.get('impersonation') and (facts.get('credential_request') or facts.get('payment_change')) and facts.get('evidence_spans'):
                votes.append({'family':'qwen','model':name,'score':None,'excerpt':' '.join(facts['evidence_spans'])})
    # A pair of heads or two SigLIP views are not independent model votes.
    independent={v['family']:v for v in votes}
    selected=None;basis=None
    if len(independent)>=2:
        selected=max(votes,key=lambda v:v['score'] or 0);basis='independent-model-agreement'
    else:
        for vote in votes:
            text=vote['excerpt']
            request=bool(re.search(r'(?is)(?:введите|укажите|сообщите|пришлите|enter|provide|send).{0,100}(?:парол|password|код.{0,25}(?:смс|вход|подтверж)|seed|cvv)|(?:выиграл|выигрыш|получите|заберите).{0,90}(?:руб|приз|подар|бонус)|(?:verify|confirm|update).{0,40}(?:account|payment|identity)',text))
            negated=bool(re.search(r'(?i)(?:никогда|не\s+(?:сообщайте|вводите|передавайте)|do not share|never share)',text))
            if (vote['score'] or 0)>=.98 and request and not negated and (report.urls or any(p.forms for p in report.pages)):
                selected=vote;basis='strong-model-and-action-context';break
    report.configuration['model_consensus']={'votes':[{k:v for k,v in x.items() if k!='excerpt'} for x in votes],
        'independent_families':len(independent),'review_suggested':bool(selected),'basis':basis,'can_confirm_phishing':False}
    if report.review.get('match')=='exact' and report.review.get('label')=='benign':
        selected=None;report.configuration['model_consensus']['review_suggested']=False
        report.configuration['model_consensus']['suppressed_by']='reviewed-benign-input'
    if selected:
        report.reason_codes.append(Evidence('AI_MODEL_REVIEW',Severity.MEDIUM,
            'Оценка локальных моделей указывает на фишинговый сценарий',
            {'ai_based':True,'models':[v['model'] for v in votes],'basis':basis,
             'model_excerpt':selected['excerpt'][:1600],'blocking':False},independent_group='model',scope_id='message'))


def verified_login(report):
    from .policy import catalog,credential_host
    forms=[(p,f) for p in report.pages for f in p.forms if set(f.sensitive_types)&{'password','otp','card','wallet_secret'}]
    return bool(forms and all(p.complete and p.identity_source in {'dom','ocr'} and f.collector_observed and any(
        b['name'] in p.claimed_brands and credential_host(p.host,b,f.sensitive_types) and credential_host(f.destination_host,b,f.sensitive_types)
        for b,_ in catalog()) for p,f in forms))


def verified_action(report):
    from .policy import catalog,credential_host,effective_host
    from .urltools import auxiliary_link
    targets=[u for u in report.urls if u.source in {'html:a:href','text','link-wrapper'} and not auxiliary_link(u)]
    names={b.brand for b in report.brands}
    return bool(targets and names and all(any(b['name'] in names and credential_host(effective_host(u),b,['password'])
        for b,_ in catalog()) for u in targets))
