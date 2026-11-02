"""Read mail/capture corpora directly from ZIP; replay never accesses the net."""
from __future__ import annotations

import collections
import hashlib
import json
import re
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .analyzer import Analyzer
from .kb import initialize_empty_kb
from .network import FetchResult
from .urltools import ioc_url_key, normalize_url


@dataclass
class Sample:
    id: str
    brand: str
    mail: bytes
    pages: dict[str, FetchResult]
    capture_members: list[str]


def read_corpus(path: Path):
    with zipfile.ZipFile(path) as archive:
        files = {i.filename: i for i in archive.infolist() if not i.is_dir()}
        if len(files) > 100000 or sum(i.file_size for i in files.values()) > 2 * 1024**3:
            raise ValueError("Corpus archive exceeds limits")
        mails = [n for n in files if re.fullmatch(r"[0-9a-f]{40}", PurePosixPath(n).name) and PurePosixPath(n).parent.name == PurePosixPath(n).name]
        for member in mails:
            mail_path = PurePosixPath(member)
            brand = "/".join(mail_path.parts[1:-2])
            prefix = str(mail_path.parent) + "/"
            pages, captures = {}, []
            for name in files:
                if not name.startswith(prefix) or not name.endswith("/html.html"):
                    continue
                if files[name].file_size > 50 * 1024**2:
                    continue
                parent = name.rsplit("/", 1)[0]
                meta_name = parent + "/chain_info.json"
                metadata = json.loads(archive.read(meta_name)) if meta_name in files else {}
                url_name = parent + "/url.txt"
                raw = metadata.get("initial_url", {}).get("value")
                if not raw and url_name in files:
                    raw = archive.read(url_name).decode("utf-8", "replace").strip()
                try:
                    key = ioc_url_key(raw or "")
                except ValueError:
                    continue
                chain = metadata.get("redirect_chain") or []
                # Corpus schemas may use URL objects or strings for redirects.
                hops = [h if isinstance(h, str) else h.get("url", h.get("value", "")) for h in chain]
                hops = [h for h in hops if isinstance(h, str) and h.startswith(("http://", "https://"))]
                final = hops[-1] if hops else raw
                result = FetchResult(archive.read(name), final, [normalize_url(h).redacted for h in [raw, *hops]], "text/html", "CAPTURED", navigation_chain=[raw,*hops])
                pages[key] = result
                captures.append(name)
            if files[member].file_size > 50 * 1024**2:
                continue
            yield Sample(mail_path.name, brand, archive.read(member), pages, captures)


def replay_fetch(pages):
    def fetch(url, limits):
        key = ioc_url_key(url)
        if key not in pages:
            raise LookupError("No recorded response; live network is disabled")
        return pages[key]
    return fetch


def _russian_brand(brand):
    return bool(re.search(r"[А-Яа-яЁё]",brand) or brand.casefold() in {"wildberries","ozon","mailru","moc ру","dsl.su","drweb","pony express"})


def benchmark_corpus(path: Path, *, max_items=None, output=None, progress=None, profile="quality", russian_only=False):
    """No runtime IOC/sample fitting. Separate mail, reached route and captures."""
    rows = []
    with tempfile.TemporaryDirectory(prefix="antiphish-eval-") as temp:
        kb = Path(temp) / "empty.sqlite"
        initialize_empty_kb(kb)
        analyzer = Analyzer(kb)
        for index, sample in enumerate(read_corpus(path)):
            if russian_only and not _russian_brand(sample.brand):continue
            if max_items is not None and len(rows) >= max_items:
                break
            static = analyzer.analyze(sample.mail, name="capture.eml", profile=profile)
            replay = analyzer.analyze(sample.mail, name="capture.eml", profile=profile, network="http", fetcher=replay_fetch(sample.pages))
            captured = [analyzer.analyze(page.body, name="capture.html", base_url=page.final_url, profile=profile) for page in sample.pages.values()]
            family = hashlib.sha256("|".join(sorted(p.sha256 for r in captured for p in r.pages)).encode()).hexdigest()[:16]
            rows.append({"id":sample.id, "brand":sample.brand, "family":family, "label":"provider-phishing-unreviewed", "mail":static.verdict.value, "route":replay.verdict.value, "mail_status":static.analysis_status.value, "route_status":replay.analysis_status.value, "network_status":replay.configuration["network_analysis_status"], "captures":[r.verdict.value for r in captured], "capture_statuses":[r.analysis_status.value for r in captured], "route_codes":sorted({e.code for e in replay.reason_codes}), "capture_codes":[sorted({e.code for e in r.reason_codes}) for r in captured], "reached_pages":len(replay.pages)-len(static.pages), "available_pages":len(sample.pages)})
            if progress and len(rows) % 25 == 0:
                progress(len(rows))
            if output and len(rows) % 25 == 0:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps({"status":"RUNNING", "rows":rows}, ensure_ascii=False), encoding="utf-8")
    russian = [r for r in rows if _russian_brand(r['brand'])]

    def metrics(items):
        return {"emails":len(items), "mail_verdicts":dict(collections.Counter(r["mail"] for r in items)), "route_verdicts":dict(collections.Counter(r["route"] for r in items)), "capture_verdicts":dict(collections.Counter(v for r in items for v in r["captures"])), "mail_statuses":dict(collections.Counter(r["mail_status"] for r in items)), "route_statuses":dict(collections.Counter(r["route_status"] for r in items)), "network_statuses":dict(collections.Counter(r["network_status"] for r in items)), "capture_statuses":dict(collections.Counter(v for r in items for v in r["capture_statuses"])), "available_captures":sum(r["available_pages"] for r in items), "reached_pages":sum(r["reached_pages"] for r in items), "brands":dict(collections.Counter(r["brand"] for r in items))}
    result = {"schema_version":"2.0", "corpus":path.name, "network":"recorded-only", "knowledge_base":"empty", "labels":"provider labels; landing/error/legitimate captured pages are not assumed phishing", "family_field":"exact capture-set fingerprint, not a verified campaign or an independent test split", "evaluation_scope":"exploratory corpus used during development; not held-out production recall", "all":metrics(rows), "russian":metrics(russian), "rows":rows}
    result["profile"] = profile
    result['selection']={'russian_brand_labels_only':russian_only,'max_items':max_items,'language_is_inferred_from_brand_label':True}
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
