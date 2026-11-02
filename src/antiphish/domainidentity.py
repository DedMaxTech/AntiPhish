"""Narrow lookalike-domain observations against the curated brand catalog.

This is a conservative subset of Unicode confusables, not a full UTS #39
implementation. Neither IDNs nor Cyrillic domains are suspicious by themselves.
Operational URLs are never rewritten with this skeleton.
"""
import unicodedata
from functools import lru_cache

import idna

from .models import Evidence,Severity

_LOOKALIKES=str.maketrans({'а':'a','е':'e','о':'o','р':'p','с':'c','у':'y','х':'x',
                         'і':'i','ј':'j','ӏ':'l','һ':'h','ԁ':'d','ԛ':'q','ѕ':'s',
                         'α':'a','ο':'o','ρ':'p','ν':'v','ι':'i','κ':'k','τ':'t'})


def skeleton(value):
    return unicodedata.normalize('NFKC',value).casefold().translate(_LOOKALIKES)


@lru_cache(maxsize=4096)
def lookalikes(host):
    if not host or 'xn--' not in host:return ()
    from .brands import load_brands
    from .urltools import normalize_url
    matches=[]
    try:observed=normalize_url('https://'+host+'/')
    except ValueError:return ()
    try:unicode_domain=idna.decode(observed.registered_domain)
    except idna.IDNAError:return ()
    candidate=skeleton(unicode_domain)
    if not candidate.isascii() or candidate==unicode_domain:return ()
    for brand in load_brands():
        for domain in brand['domains']:
            try:official=normalize_url('https://'+domain+'/')
            except ValueError:continue
            if observed.registered_domain==official.registered_domain:continue
            if official.registered_domain==candidate:
                matches.append((brand['name'],unicode_domain,official.registered_domain))
    return tuple(dict.fromkeys(matches))


def annotate(report):
    for item in report.urls:
        matches=lookalikes(item.host)
        if not matches:continue
        if 'BRAND_HOMOGRAPH' not in item.flags:item.flags.append('BRAND_HOMOGRAPH')
        report.reason_codes.append(Evidence('BRAND_HOMOGRAPH',Severity.MEDIUM,
            'Домен визуально похож на официальный домен бренда',
            {'host':item.host,'matches':[{'brand':b,'unicode_domain':u,'official_domain':d} for b,u,d in matches],'blocking':False},
            independent_group='url',scope_id=item.scope_id))
    for page in report.pages:
        matches=lookalikes(page.host)
        if not matches or not page.complete or page.identity_source!='dom':continue
        for form in page.forms:
            types=set(form.sensitive_types)&{'password','otp','wallet_secret'}
            if not types or not form.collector_observed or not form.destination_host:continue
            from .policy import credential_host,catalog
            brands={b['name']:b for b,_ in catalog()}
            foreign=[(b,u,d) for b,u,d in matches if b in brands and not credential_host(form.destination_host,brands[b],form.sensitive_types)]
            if not foreign:continue
            report.reason_codes.append(Evidence('LOOKALIKE_SECRET_FORM',Severity.HIGH,
                'Форма запрашивает секрет на домене-двойнике известного сервиса',
                {'form_id':form.id,'host':page.host,'matches':[{'brand':b,'unicode_domain':u,'official_domain':d} for b,u,d in foreign],
                 'destination':form.destination,'blocking':False},independent_group='route',scope_id=page.id))
