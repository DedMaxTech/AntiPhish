from __future__ import annotations

import json
import re
import collections
from functools import lru_cache
from pathlib import Path

from .config import RESOURCE_DIR
from .models import BrandFinding, Evidence, Severity, UrlFinding
from .urltools import same_site


def load_brands(path: Path | None = None) -> list[dict]:
    source = path or RESOURCE_DIR / 'brands.json'
    stat = source.stat()
    return _load_cached(str(source), stat.st_size, stat.st_mtime_ns)


@lru_cache(maxsize=8)
def _load_cached(path, size, mtime):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return [b for b in payload["brands"] if b.get("active") and b.get("domains") and len(b.get("references", [])) >= 2]


def detect_brands(text: str, urls: list[UrlFinding], sender_domain: str | None = None, high_risk_context: bool = False) -> tuple[list[BrandFinding], list[Evidence]]:
    haystack = text.casefold()
    findings: list[BrandFinding] = []
    evidence: list[Evidence] = []
    observed = sorted({u.host for u in urls if u.host} | ({sender_domain} if sender_domain else set()))
    for brand in load_brands():
        aliases = [a.casefold() for a in brand.get("aliases", []) if len(a.strip()) >= 4]
        matched = [a for a in aliases if re.search(r"(?<!\w)" + re.escape(a) + r"(?!\w)", haystack)]
        if not matched:
            continue
        official = brand["domains"]
        bad_hosts = [host for host in observed if not any(same_site(host, domain) for domain in official)]
        good_hosts = [host for host in observed if any(same_site(host, domain) for domain in official)]
        confidence = min(0.99, 0.72 + 0.05 * len(set(matched)))
        findings.append(BrandFinding(brand=brand["name"], confidence=confidence, sources=["text-alias"], official_domains=official, observed_domains=observed))
        # A mixed legitimate and external page is common in newsletters. Record a
        # mismatch only if there is no official destination or the external host
        # is tied to a form/visible-link destination.
        consequential = {
            u.host for u in urls
            if u.host and (u.source in {"form-action", "meta-refresh"} or (u.displayed_text and "http" in u.displayed_text.lower()))
        }
        relevant_bad = sorted(set(bad_hosts).intersection(consequential))
        credential_context = bool(re.search(r"(?i)(?:login|log in|sign in|password|account verification|verify account|войти|парол|подтверд.{0,20}(?:аккаунт|уч[её]тн))", text))
        host_counts = collections.Counter(u.host for u in urls if u.host and u.host in bad_hosts)
        dominant_bad = [host for host, count in host_counts.items() if count >= 2]
        if high_risk_context and (relevant_bad or (bad_hosts and not good_hosts and credential_context and dominant_bad)):
            evidence.append(Evidence(
                code="BRAND_DOMAIN_MISMATCH", severity=Severity.HIGH,
                summary=f"Бренд {brand['name']} используется вне подтверждённого домена",
                details={"brand": brand["name"], "observed_domains": relevant_bad or dominant_bad, "official_domains": official},
                independent_group="brand",
            ))
    return findings, evidence
