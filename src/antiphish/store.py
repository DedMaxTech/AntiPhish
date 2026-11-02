"""Local report history and content-addressed original/evidence snapshots."""
from __future__ import annotations

import json
import sqlite3
import uuid
import hashlib
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
            con.execute('CREATE TABLE IF NOT EXISTS artifact_blobs(id TEXT PRIMARY KEY,data BLOB NOT NULL)')
            con.execute('CREATE TABLE IF NOT EXISTS report_artifacts(report_id TEXT NOT NULL,id TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,media_type TEXT NOT NULL,PRIMARY KEY(report_id,id,kind))')
            con.commit()

    def connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def put(self, report, source_id: str | None = None) -> str:
        identifier = uuid.uuid4().hex
        materials = []
        if hasattr(report, 'to_dict'):
            if report.model_image:
                materials.append(('image','model-input.png','image/png',report.model_image))
            if report.source_bytes:
                materials.append(('original',report.input.get('name','source.eml'),'application/octet-stream',report.source_bytes))
            from .contexts import redact
            learning = {'pages':report.learning_pages,'message_signature':report.learning_signature,'message_text':report.learning_message,
                'urls':[{'display':u.original,'context_display':redact(u.original,8192),'full':u.navigation_url or u.normalized or u.original} for u in report.urls]}
            materials.append(('learning','learning.json','application/json',json.dumps(learning,ensure_ascii=False).encode()))
            for page in report.pages:
                if page.image_bytes:
                    materials.append(('image',page.id+'.png','image/png',page.image_bytes))
                for index,view in enumerate(page.visual_images):
                    materials.append(('image',page.id+'-view-'+str(index)+'.png','image/png',view['bytes']))
            report = report.to_dict()
        source_id = source_id or report.get('input',{}).get('name') or report.get('input',{}).get('value')
        with closing(self.connect()) as con, con:
            con.execute("INSERT INTO reports VALUES(?,?,?,?,?,?)", (identifier, datetime.now(timezone.utc).isoformat(), report["verdict"], report["analysis_status"], source_id, json.dumps(report, ensure_ascii=False)))
            for kind,name,media_type,data in materials:
                digest = hashlib.sha256(data).hexdigest()
                con.execute('INSERT OR IGNORE INTO artifact_blobs VALUES(?,?)',(digest,data))
                con.execute('INSERT OR IGNORE INTO report_artifacts VALUES(?,?,?,?,?)',(identifier,digest,kind,name,media_type))
        return identifier

    def get(self, identifier: str) -> dict | None:
        with closing(self.connect()) as con:
            row = con.execute("SELECT created_at,source_id,payload FROM reports WHERE id=?", (identifier,)).fetchone()
        return {"report_id": identifier, "created_at": row[0], "source_id": row[1], "report": json.loads(row[2]), 'artifacts':self.artifacts(identifier)} if row else None

    def artifacts(self, identifier: str) -> list[dict]:
        with closing(self.connect()) as con:
            rows = con.execute('SELECT a.id,a.kind,a.name,a.media_type,length(b.data) FROM report_artifacts a JOIN artifact_blobs b ON b.id=a.id WHERE a.report_id=? AND a.kind<>?',(identifier,'learning')).fetchall()
        return [dict(zip(('id','kind','name','media_type','bytes'),row)) for row in rows]

    def artifact(self, identifier: str, digest: str, *, kind: str | None = None):
        with closing(self.connect()) as con:
            row = con.execute('SELECT a.kind,a.name,a.media_type,b.data FROM report_artifacts a JOIN artifact_blobs b ON b.id=a.id WHERE a.report_id=? AND a.id=?'+(' AND a.kind=?' if kind else ''), (identifier,digest,kind) if kind else (identifier,digest)).fetchone()
        return dict(zip(('kind','name','media_type','data'),row)) if row else None

    def learning(self, identifier: str) -> dict:
        with closing(self.connect()) as con:
            row = con.execute('SELECT b.data FROM report_artifacts a JOIN artifact_blobs b ON b.id=a.id WHERE a.report_id=? AND a.kind=?',(identifier,'learning')).fetchone()
        return json.loads(row[0]) if row else {}

    def clone_materials(self, original: str, target: str):
        with closing(self.connect()) as con, con:
            con.execute('INSERT OR IGNORE INTO report_artifacts SELECT ?,id,kind,name,media_type FROM report_artifacts WHERE report_id=?',(target,original))

    def recent(self, limit: int = 50) -> list[dict]:
        with closing(self.connect()) as con:
            rows = con.execute("SELECT id,created_at,verdict,status,source_id FROM reports ORDER BY rowid DESC LIMIT ?", (min(1000, max(1, limit)),)).fetchall()
        return [dict(zip(("report_id", "created_at", "verdict", "analysis_status", "source_id"), row)) for row in rows]

