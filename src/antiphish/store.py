"""Local report history. Original messages and screenshots are not stored here."""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


class ReportStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, verdict TEXT NOT NULL, status TEXT NOT NULL, source_id TEXT, payload TEXT NOT NULL)")
            con.commit()

    def connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def put(self, report: dict, source_id: str | None = None) -> str:
        identifier = uuid.uuid4().hex
        with closing(self.connect()) as con, con:
            con.execute("INSERT INTO reports VALUES(?,?,?,?,?,?)", (identifier, datetime.now(timezone.utc).isoformat(), report["verdict"], report["analysis_status"], source_id, json.dumps(report, ensure_ascii=False)))
        return identifier

    def get(self, identifier: str) -> dict | None:
        with closing(self.connect()) as con:
            row = con.execute("SELECT created_at,source_id,payload FROM reports WHERE id=?", (identifier,)).fetchone()
        return {"report_id": identifier, "created_at": row[0], "source_id": row[1], "report": json.loads(row[2])} if row else None

    def recent(self, limit: int = 50) -> list[dict]:
        with closing(self.connect()) as con:
            rows = con.execute("SELECT id,created_at,verdict,status,source_id FROM reports ORDER BY rowid DESC LIMIT ?", (min(1000, max(1, limit)),)).fetchall()
        return [dict(zip(("report_id", "created_at", "verdict", "analysis_status", "source_id"), row)) for row in rows]

