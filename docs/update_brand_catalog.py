"""Check candidate official roots; do not activate unresolved corpus identities.

Run manually when curating the catalog. HTTP reachability alone is insufficient:
accepted records must also expose an expected identity in their HTML title.
The saved verification log is review material, not an automatic SAFE feed.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from dataclasses import replace
import json
import re
import sys

from antiphish.config import DEFAULT_LIMITS, RESOURCE_DIR
from antiphish.network import safe_http_get
from antiphish.urltools import normalize_url

# name | aliases | official domains | title identity expressions
CANDIDATES = '''
Dr.Web|dr.web,доктор веб,drweb|drweb.ru,drweb.com|dr.web,доктор веб,doctor web
DPD|dpd,дпд|dpd.ru,dpd.com|dpd
Pony Express|pony express,пони экспресс|ponyexpress.ru|pony,пони
Ренессанс Банк|ренессанс банк,ренессанс кредит|rencredit.ru|ренессанс
Банк Зенит|банк зенит|zenit.ru|зенит
Банк Синара|банк синара,скб-банк|sinara.ru|синара
Банк Точка|банк точка,точка банк|tochka.com|точка
Банк Солидарность|банк солидарность|solid.ru|солидарность
Росгосстрах|росгосстрах|rgs.ru|росгосстрах
Ингосстрах|ингосстрах|ingos.ru|ингосстрах
СОГАЗ|согаз|sogaz.ru|согаз
РЕСО-Гарантия|ресо-гарантия,ресо гарантия|reso.ru|ресо
СберСтрахование|сберстрахование,сбер страхование|sberins.ru|сбер
Магнит|магнит|magnit.ru|магнит
Пятёрочка|пятёрочка,пятерочка|5ka.ru|пятёрочка,пятерочка
Перекрёсток|перекрёсток,перекресток|perekrestok.ru|перекр
Лента|лента|lenta.com|лента
ВкусВилл|вкусвилл,вкус вилл|vkusvill.ru|вкусвилл
Спортмастер|спортмастер|sportmaster.ru|спортмастер
Лемана ПРО|лемана про,леруа мерлен|lemanapro.ru|лемана
Литрес|литрес,litres|litres.ru|литрес,litres
Hoff|hoff,хофф|hoff.ru|hoff
Ситилинк|ситилинк,citilink|citilink.ru|ситилинк
ВсеИнструменты|всеинструменты,все инструменты|vseinstrumenti.ru|всеинструменты
HeadHunter|headhunter,хедхантер|hh.ru|headhunter,работ
SuperJob|superjob,суперджоб|superjob.ru|superjob,работ
Работа.ру|работа.ру,rabota.ru|rabota.ru|работ
S7 Airlines|s7 airlines,s7 авиакомпания|s7.ru|s7
Уральские авиалинии|уральские авиалинии|uralairlines.ru|уральские
ЮТэйр|ютэйр,utair|utair.ru|utair,ютэйр
Туту|туту,tutu.ru|tutu.ru|туту,tutu
Ostrovok|ostrovok,островок|ostrovok.ru|ostrovok,островок
Столото|столото|stoloto.ru|столото
Роскомнадзор|роскомнадзор|rkn.gov.ru|роскомнадзор
МФЦ Москвы|мои документы,мфц москвы|md.mos.ru|мои документы,москв
Apple|apple id,apple icloud,apple support,apple appstore,icloud,apple|apple.com,icloud.com|apple,icloud
Amazon|amazon|amazon.com,amazon.co.jp,amazon.de|amazon
PayPal|paypal|paypal.com|paypal
Facebook|facebook|facebook.com,meta.com|facebook,meta
Instagram|instagram,инстаграм|instagram.com|instagram
Meta|meta account,meta business|meta.com,facebook.com|meta
Netflix|netflix|netflix.com|netflix
Spotify|spotify|spotify.com|spotify
LinkedIn|linkedin|linkedin.com|linkedin
Booking|booking.com,booking|booking.com|booking
FedEx|fedex|fedex.com|fedex
UPS|ups delivery,united parcel service|ups.com|ups
USPS|usps,united states postal service|usps.com|usps,postal
PostNL|postnl|postnl.nl|postnl
La Poste|la poste|laposte.fr|poste
Deutsche Telekom|deutsche telekom|telekom.de|telekom
Deutsche Bank|deutsche bank|db.com,deutsche-bank.de|deutsche bank
BNP Paribas|bnp paribas|bnpparibas.com,mabanque.bnpparibas|bnp,paribas
HSBC|hsbc bank,hsbc|hsbc.com,hsbc.co.uk|hsbc
Santander|santander|santander.com,santander.co.uk|santander
Bank of America|bank of america|bankofamerica.com|bank of america
Citibank|citibank,citi bank|citi.com|citi
Capital One|capital one|capitalone.com|capital one
Wells Fargo|wells fargo|wellsfargo.com|wells fargo
American Express|american express,amex|americanexpress.com|american express
Fidelity|fidelity|fidelity.com|fidelity
Coinbase|coinbase|coinbase.com|coinbase
Ledger|ledger|ledger.com|ledger
MetaMask|metamask|metamask.io|metamask
Trust Wallet|trust wallet|trustwallet.com|trust wallet
Shopify|shopify|shopify.com|shopify
QuickBooks|quickbooks|quickbooks.intuit.com,intuit.com|quickbooks,intuit
cPanel|cpanel|cpanel.net|cpanel
ShareFile|sharefile|sharefile.com|sharefile
Nintendo|nintendo|nintendo.com,nintendo.co.jp|nintendo,任天堂
PlayStation|playstation|playstation.com|playstation
TikTok|tiktok|tiktok.com|tiktok
Lufthansa|lufthansa|lufthansa.com|lufthansa
Turkish Airlines|turkish airlines|turkishairlines.com|turkish
Visa|visa|visa.com|visa
Mastercard|mastercard|mastercard.com|mastercard
'''.strip()


def check(line):
    name, aliases, domains, identities = line.split('|')
    checks, valid = [], []
    for domain in domains.split(','):
        url = 'https://' + domain + '/'
        try:
            fetched = safe_http_get(url, replace(DEFAULT_LIMITS, network_timeout_seconds=8, max_http_bytes=3*1024*1024))
            text = fetched.body.decode(fetched.charset or 'utf-8', 'replace')
            title = re.search(r'(?is)<title[^>]*>(.*?)</title>', text)
            title = re.sub('<[^>]+>', '', title.group(1)).strip() if title else ''
            final = normalize_url(fetched.final_url).host
            approved = any(identity.casefold() in title.casefold() for identity in identities.split(',')) and any(final == candidate or final.endswith('.'+candidate) for candidate in domains.split(','))
            checks.append({'url': url, 'final_url': normalize_url(fetched.final_url).redacted, 'title': title[:250], 'identity_match': approved})
            if approved:
                valid.append(domain)
        except Exception as exc:
            checks.append({'url': url, 'error': type(exc).__name__})
    return {'name': name, 'aliases': aliases.split(','), 'domains': valid, 'candidate_domains': domains.split(','), 'active': bool(valid), 'provenance': 'official-root-title-reviewed', 'verified_at': '2026-10-07', 'references': [c['url'] for c in checks if c.get('identity_match')] + [c['final_url'] for c in checks if c.get('identity_match')], 'verification': checks}


def main():
    path = RESOURCE_DIR / 'brands.json'
    payload = json.loads(path.read_text(encoding='utf-8'))
    known = {b['name'] for b in payload['brands']}
    lines = [line for line in CANDIDATES.splitlines() if line.split('|')[0] not in known]
    with ThreadPoolExecutor(max_workers=8) as pool:
        checked = list(pool.map(check, lines))
    for brand in checked:
        print(brand['name'], brand['active'], brand['domains'], flush=True)
    payload['brands'].extend(checked)
    payload['schema_version'] = '2.0'
    payload['policy'] = 'Active curated identities participate in scoped form checks. Candidate and unverified corpus identities remain inactive. The separate domain CSV never authorizes secret collectors.'
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    report = Path(__file__).resolve().parents[1] / 'reports/revision-2026-10/brand-verification.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(checked, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
