from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable


TOKEN_KEYS = re.compile(
    r"(?i)(token|code|key|auth|session|sid|jwt|ticket|signature|sig|confirm|reset|unsubscribe|email)"
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def redact_value(value: str, keep: int = 2) -> str:
    if len(value) <= keep * 2:
        return "***"
    return value[:keep] + "***" + value[-keep:]


def bounded_text(data: bytes | str, limit: int = 200_000) -> str:
    if isinstance(data, str):
        return data[:limit]
    sample = data[:limit]
    for encoding in ("utf-8", "windows-1251", "latin-1"):
        try:
            return sample.decode(encoding)
        except UnicodeDecodeError:
            pass
    return sample.decode("utf-8", errors="replace")


def simhash64(tokens: Iterable[str]) -> str:
    vector = [0] * 64
    seen = 0
    for token in tokens:
        if not token:
            continue
        seen += 1
        digest = hashlib.blake2b(token.encode("utf-8", "ignore"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        for bit in range(64):
            vector[bit] += 1 if value & (1 << bit) else -1
    if not seen:
        return "0" * 16
    result = sum(1 << bit for bit, score in enumerate(vector) if score >= 0)
    return f"{result:016x}"


def pasted_name(data: bytes, prefix="pasted") -> str:
    is_html = re.search(rb"(?is)^\s*(?:<!doctype\s+html|<html|<head|<body|<form|<h[1-6]|<div|<script|<a\s)",data[:4096])
    return prefix + (".html" if is_html else ".eml")
