"""Navigation intent, separate from page resources and footer/service links."""
import re
from urllib.parse import urlsplit

ACTION=re.compile(r'(?i)(?:получ|забра|провер|подтверд|войти|вход|открыть|просмотр|оплат|восстанов|продолж|активир|claim|verify|sign in|log in|open|view|review|pay|continue|download.{0,12}(?:document|invoice))')
SERVICE=re.compile(r'(?i)(?:отпис|unsubscribe|privacy|условия\s+использования|политика\s+(?:конфиденциальности|обработки)|terms of (?:use|service)|пользовательск.{0,12}соглашени|report abuse|сообщить о нарушении|скачать.{0,15}прилож|app store|google play|посмотреть.{0,15}в браузере|view.{0,15}in.{0,5}browser)|^(?:в\s+разделе\s+)?(?:помощь|центр\s+поддержки|служба\s+поддержки)$')
RESOURCE_SUFFIXES={'.css','.js','.mjs','.map','.png','.jpg','.jpeg','.gif','.svg','.webp','.ico','.bmp','.avif','.woff','.woff2','.ttf','.otf','.eot','.mp3','.mp4','.webm','.avi','.mov'}
TRACKERS={'googletagmanager.com','google-analytics.com','googletagservices.com','mc.yandex.ru','top-fwz1.mail.ru','stats.g.doubleclick.net','connect.facebook.net'}


def service_reason(item,_depth=0):
    host=(item.host or '').lower();path=urlsplit(item.navigation_url or item.normalized or '').path.lower()
    if any(host==h or host.endswith('.'+h) for h in TRACKERS):return 'Аналитика или счётчик'
    if host in {'apps.apple.com','play.google.com','app.adjust.com'}:return 'Ссылка на приложение'
    if host in {'support.google.com','policies.google.com'} and path.startswith(('/accounts/answer/','/privacy','/terms')):return 'Справка или политика платформы'
    if SERVICE.search(item.displayed_text or ''):return 'Служебная ссылка'
    if re.search(r'/(?:unsubscribe|unsub|optout|opt-out|privacy|legal|terms)(?:[/.?_-]|$)',path):return 'Служебная ссылка'
    if item.navigation_role=='service':return 'Ссылка в подвале или меню'
    if item.host=='docs.google.com' and (path.rstrip('/') in {'/forms','/forms/create'} or path.endswith('/reportabuse')):return 'Ссылка платформы формы'
    if host in {'avito.ru','www.avito.ru'} and path.rstrip('/')=='/apps':return 'Ссылка на приложение'
    if _depth<3:
        from .urltools import unwrap_url,normalize_url
        from .models import UrlFinding
        target=unwrap_url(item.navigation_url or item.normalized or item.original)
        if target:
            n=normalize_url(target)
            return service_reason(UrlFinding(n.redacted,normalized=n.normalized,host=n.host,displayed_text=item.displayed_text),_depth+1)
    return None


def priority(item,hidden_redirect=False):
    source=item.source or '';path=urlsplit(item.navigation_url or item.normalized or '').path.lower()
    if source=='input':item.navigation_role='input';item.selection_reason='Входной URL';return 200
    reason=service_reason(item)
    if reason:item.navigation_role='service';item.selection_reason=reason;return None
    if any(path.endswith(s) for s in RESOURCE_SUFFIXES):
        item.navigation_role='resource';item.selection_reason='Ресурс страницы';return None
    values={'hosted-document':170,'link-wrapper':130,'javascript-navigation':110,'meta-refresh':125,
            'html:a:href':100,'html:area:href':100,'html:iframe:src':95,'html:frame:src':95,'text':75}
    score=120 if source.startswith('qr:') else 80 if source.startswith(('pdf:','office:')) else values.get(source)
    if score is None:
        item.navigation_role='resource';item.selection_reason='Не является переходом пользователя';return None
    if source.startswith('html:') and 'frame:' in source:
        item.navigation_role='embedded-document';item.selection_reason='Встроенный документ'
    elif source=='hosted-document':item.navigation_role='embedded-document';item.selection_reason='Содержимое опубликованного документа'
    elif item.navigation_role=='action' or ACTION.search(item.displayed_text or ''):
        item.navigation_role='action';item.selection_reason='Ссылка действия в содержимом';score+=35
    else:item.navigation_role='link';item.selection_reason='Ссылка в содержимом'
    if item.displayed_text:score+=5
    if set(item.flags)&{'URL_SHORTENER','MIXED_SCRIPT_HOST','IP_LITERAL','USERINFO_IN_URL'}:score+=10
    return score


def published_sheet_targets(markup,base):
    """Only same-document sheet literals, not arbitrary JS URL strings."""
    from .htmlanalysis import decode_script_literals
    from .urltools import normalize_url
    root=urlsplit(base)
    if root.hostname!='docs.google.com' or not re.fullmatch(r'/spreadsheets/d/(?:e/)?[^/]+/pubhtml',root.path):return []
    decoded=decode_script_literals(markup[:1_000_000]);result=[]
    for m in re.finditer(r'''pageUrl\s*:\s*['"]([^'"]+)''',decoded):
        try:
            target=normalize_url(m[1]);p=urlsplit(target.normalized)
            if p.hostname==root.hostname and p.path==root.path+'/sheet' and target.normalized not in result:result.append(target.normalized)
        except ValueError:continue
    return result[:6]
