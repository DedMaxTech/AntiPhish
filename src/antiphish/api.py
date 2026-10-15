"""Internal synchronous API; one analyzer, no accounts or task broker."""
from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
from contextlib import closing
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from . import __version__
from .analyzer import Analyzer
from .batch import run_batch
from .config import DEFAULT_KB, REPORT_DIR
from .runtime import manifest
from .store import ReportStore


class _BodyTooLarge(HTTPException):
    def __init__(self):
        super().__init__(413, 'Request body limit exceeded')


class BodyLimit:
    """Bound chunked uploads before the multipart parser spools them to disk."""
    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        from starlette.responses import JSONResponse
        headers = dict(scope.get('headers', []))
        try:
            length = int(headers.get(b'content-length', b'0'))
        except ValueError:
            return await JSONResponse({'detail':'Invalid Content-Length'}, status_code=400)(scope,receive,send)
        if length > self.limit:
            return await JSONResponse({'detail':'Request body limit exceeded'}, status_code=413)(scope,receive,send)
        size = 0
        async def bounded_receive():
            nonlocal size
            message = await receive()
            size += len(message.get('body', b''))
            if size > self.limit:
                raise _BodyTooLarge()
            return message
        try:
            await self.app(scope, bounded_receive, send)
        except _BodyTooLarge:
            await JSONResponse({'detail':'Request body limit exceeded'}, status_code=413)(scope,receive,send)

Profile = Literal['fast', 'quality', 'deep']
Network = Literal['offline', 'http', 'browser']


class AnalyzeRequest(BaseModel):
    source: str = Field(description='URL или путь к файлу на машине API')
    profile: Profile = 'quality'
    network: Network = 'offline'
    confirm_browser_risk: str | None = None
    persist: bool = True


class BatchRequest(AnalyzeRequest):
    source: str = Field(description='Папка, ZIP или TAR на машине API')
    extensions: list[str] | None = None
    pattern: str = '*'


def create_app(kb_path: Path = DEFAULT_KB, store_path: Path | None = None) -> FastAPI:
    app = FastAPI(title='AntiPhish', version=__version__, description='Внутренний локальный API. NOT_DETECTED не гарантирует безопасность. Проверяйте analysis_status и network_analysis_status. Запросы выполняются синхронно; при deep модели остаются в памяти процесса.')
    analyzer = Analyzer(Path(kb_path))
    app.add_middleware(BodyLimit, limit=analyzer.limits.max_input_bytes + 1024*1024)
    store = ReportStore(store_path or REPORT_DIR / 'history.sqlite')
    lock = threading.Lock()  # OCR budgets and GPU model caches belong to this process.
    app.state.analyzer, app.state.store = analyzer, store

    def check(network, confirmation):
        if network == 'browser' and confirmation != 'I_UNDERSTAND':
            raise HTTPException(422, 'Browser mode requires confirm_browser_risk=I_UNDERSTAND')

    def upload(file):
        if not file.filename:
            raise HTTPException(422, 'Filename is required')
        data = file.file.read(analyzer.limits.max_input_bytes + 1)
        if len(data) > analyzer.limits.max_input_bytes:
            raise HTTPException(413, 'Input byte limit exceeded')
        return data

    @app.get('/health', tags=['Система'])
    def health():
        return {'status': 'OK', 'runtime': manifest(analyzer.kb.path)}

    @app.get('/reasons', tags=['Система'])
    def reasons():
        from .reason_codes import catalog
        return {'reasons': catalog()}

    @app.get('/knowledge', tags=['Система'])
    def knowledge():
        from .reputation import status
        counts = {}
        if analyzer.kb.path.exists():
            with closing(analyzer.kb.connect()) as con:
                for table in ('brands', 'known_hashes', 'url_iocs', 'behavior_templates'):
                    if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                        counts[table] = con.execute('SELECT count(*) FROM ' + table).fetchone()[0]
        return {'counts': counts, 'reputation': status(analyzer.kb.reputation_path)}

    def single(source, name, profile, network, confirmation, persist):
        check(network, confirmation)
        with lock:
            payload = analyzer.analyze(source, name=name, profile=profile, network=network, browser_confirmation=confirmation).to_dict()
            identifier = store.put(payload) if persist else None
        return {'report_id': identifier, 'report': payload}

    @app.post('/analyze', tags=['Анализ'])
    def analyze(request: AnalyzeRequest):
        return single(request.source, None, request.profile, request.network, request.confirm_browser_risk, request.persist)

    @app.post('/analyze/file', tags=['Анализ'])
    def analyze_file(file: UploadFile = File(...), profile: Profile = Form('quality'), network: Network = Form('offline'), confirm_browser_risk: str | None = Form(None), persist: bool = Form(True)):
        return single(upload(file), Path(file.filename).name, profile, network, confirm_browser_risk, persist)

    @app.post('/batch', tags=['Пакетный анализ'])
    def batch(request: BatchRequest):
        check(request.network, request.confirm_browser_risk)
        path = Path(request.source)
        if not path.exists():
            raise HTTPException(404, 'Batch source not found')
        with lock:
            return run_batch(path, analyzer, profile=request.profile, network=request.network, browser_confirmation=request.confirm_browser_risk, extensions=request.extensions, pattern=request.pattern, store=store if request.persist else None)

    @app.post('/batch/file', tags=['Пакетный анализ'])
    def batch_file(file: UploadFile = File(...), profile: Profile = Form('quality'), network: Network = Form('offline'), confirm_browser_risk: str | None = Form(None), extensions: str | None = Form(None, description='Расширения через запятую, например .eml,.html'), persist: bool = Form(True)):
        check(network, confirm_browser_risk)
        with tempfile.TemporaryDirectory(prefix='antiphish-batch-') as directory:
            path = Path(directory) / Path(file.filename or 'batch.zip').name
            path.write_bytes(upload(file))
            with lock:
                result = run_batch(path, analyzer, profile=profile, network=network, browser_confirmation=confirm_browser_risk, extensions=extensions.split(',') if extensions else None, store=store if persist else None)
            result['source'] = file.filename
            return result

    @app.get('/reports', tags=['История'])
    def reports(limit: int = 50):
        return {'reports': store.recent(limit)}

    @app.get('/reports/{identifier}', tags=['История'])
    def report(identifier: str):
        result = store.get(identifier)
        if result is None:
            raise HTTPException(404, 'Report not found')
        return result

    return app


def main():
    import uvicorn
    uvicorn.run(create_app(), host=os.environ.get('ANTIPHISH_API_HOST', '127.0.0.1'), port=int(os.environ.get('ANTIPHISH_API_PORT', '8000')), workers=1)

