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
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
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
        if scope.get('method') in {'POST','PUT','PATCH','DELETE'} and headers.get(b'origin'):
            from urllib.parse import urlsplit
            try:
                origin=urlsplit(headers[b'origin'].decode('latin-1'))
            except ValueError:
                return await JSONResponse({'detail':'Invalid Origin'},status_code=403)(scope,receive,send)
            if origin.scheme not in {'http','https'} or origin.netloc.lower()!=headers.get(b'host',b'').decode('latin-1').lower():
                return await JSONResponse({'detail':'Запись из другого сайта запрещена; используйте локальный интерфейс или внутренний API-клиент.'},status_code=403)(scope,receive,send)
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

Profile = Literal['fast', 'quality', 'deep', 'custom']
Network = Literal['offline', 'http', 'browser']


class AnalyzeRequest(BaseModel):
    source: str = Field(description='URL или путь к файлу на машине API')
    profile: Profile = 'quality'
    network: Network = 'offline'
    confirm_browser_risk: str | None = None
    persist: bool = True
    options: dict[str,bool|int] | None = None


class BatchRequest(AnalyzeRequest):
    source: str = Field(description='Папка, ZIP или TAR на машине API')
    extensions: list[str] | None = None
    pattern: str = '*'


class ReviewRequest(BaseModel):
    report_id: str
    label: Literal['phishing', 'benign']
    comment: str = Field(default='', max_length=2000)
    page_ids: list[str] = Field(default_factory=list, max_length=50)


class EntryLabel(BaseModel):
    label: Literal['phishing','benign','unreviewed']


class Indicator(BaseModel):
    value: str = Field(max_length=8192)
    source: str = Field(default='Добавлено вручную',max_length=1000)


def create_app(kb_path: Path = DEFAULT_KB, store_path: Path | None = None) -> FastAPI:
    app = FastAPI(title='AntiPhish', version=__version__, description='Внутренний локальный API. NOT_DETECTED не гарантирует безопасность. Проверяйте analysis_status и network_analysis_status. Запросы выполняются синхронно; при deep модели остаются в памяти процесса.')
    analyzer = Analyzer(Path(kb_path))
    app.add_middleware(BodyLimit, limit=analyzer.limits.max_input_bytes + 1024*1024)
    store = ReportStore(store_path or REPORT_DIR / 'history.sqlite')
    lock = threading.Lock()  # OCR budgets and GPU model caches belong to this process.
    app.state.analyzer, app.state.store = analyzer, store
    web = Path(__file__).parent / 'web'
    if web.is_dir():
        app.mount('/assets', StaticFiles(directory=web), name='assets')

        @app.get('/', include_in_schema=False)
        def index():
            return FileResponse(web/'index.html',headers={
                'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
                'Referrer-Policy':'no-referrer', 'X-Content-Type-Options':'nosniff'})

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

    @app.get('/components', tags=['Система'])
    def components_status():
        from .layamodel import status as laya_status
        from .ocr import status as ocr_status
        return {'laya':laya_status(),'ocr':ocr_status()}

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
                for table in ('brands', 'known_hashes', 'url_iocs', 'behavior_templates','reviewed_samples'):
                    if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                        counts[table] = con.execute('SELECT count(*) FROM ' + table).fetchone()[0]
        counts.setdefault('reviewed_samples',0)
        from .brands import load_brands
        counts['brands']=len(load_brands())
        if counts.get('behavior_templates'):
            with closing(analyzer.kb.connect()) as con:
                counts['templates_with_sensitive_fields']=con.execute("SELECT count(*) FROM behavior_templates WHERE sensitive_types<>'[]'").fetchone()[0]
        gallery={}
        try:
            from .logogallery import reviewed_references
            refs=reviewed_references()
            gallery={'references':len(refs),'brands':sorted({r['brand'] for r in refs}),'calibrated':False,
                     'items':[{'brand':r['brand'],'sha256':r['sha256'],'source_url':r['source_url'],'kind':r.get('kind','symbol')} for r in refs]}
        except (OSError,ValueError):
            pass
        return {'counts': counts, 'reputation': status(analyzer.kb.reputation_path),'logo_gallery':gallery}

    @app.get('/knowledge/logos/{digest}', tags=['Система'])
    def logo_reference(digest: str):
        import json, hashlib
        try:
            from .logogallery import reviewed_references
            record=next((r for r in reviewed_references() if r.get('sha256')==digest),None)
            if not record:
                raise ValueError('Unknown reference')
            blob=Path(record['_file']).read_bytes()
            if hashlib.sha256(blob).hexdigest()==digest:
                return Response(blob,media_type='image/png',headers={'Cache-Control':'private, max-age=86400'})
        except (OSError,ValueError,KeyError):
            pass
        raise HTTPException(404,'Эталон недоступен')

    def component_options(profile,value):
        import json
        from .options import resolve
        try:
            raw=json.loads(value) if isinstance(value,str) and value else value
            if raw is not None and not isinstance(raw,dict):
                raise ValueError("Options must be an object")
            resolve(profile,raw)
            return raw
        except (ValueError,TypeError) as exc:
            raise HTTPException(422,str(exc)) from exc

    def single(source, name, profile, network, confirmation, persist, options=None):
        check(network, confirmation)
        options=component_options(profile,options)
        with lock:
            report = analyzer.analyze(source, name=name, profile=profile, network=network, browser_confirmation=confirmation,options=options)
            identifier = store.put(report) if persist else None
        return {'report_id': identifier, 'report': report.to_dict(), 'artifacts':store.artifacts(identifier) if identifier else []}

    @app.post('/analyze', tags=['Анализ'])
    def analyze(request: AnalyzeRequest):
        return single(request.source, None, request.profile, request.network, request.confirm_browser_risk, request.persist,request.options)

    @app.post('/analyze/file', tags=['Анализ'])
    def analyze_file(file: UploadFile = File(...), profile: Profile = Form('quality'), network: Network = Form('offline'), confirm_browser_risk: str | None = Form(None), persist: bool = Form(True), options: str | None = Form(None)):
        return single(upload(file), Path(file.filename).name, profile, network, confirm_browser_risk, persist,options)

    @app.post('/batch', tags=['Пакетный анализ'])
    def batch(request: BatchRequest):
        check(request.network, request.confirm_browser_risk)
        path = Path(request.source)
        if not path.exists():
            raise HTTPException(404, 'Batch source not found')
        with lock:
            return run_batch(path, analyzer, profile=request.profile, network=request.network, browser_confirmation=request.confirm_browser_risk, extensions=request.extensions, pattern=request.pattern, store=store if request.persist else None,options=component_options(request.profile,request.options))

    @app.post('/batch/file', tags=['Пакетный анализ'])
    def batch_file(file: UploadFile = File(...), profile: Profile = Form('quality'), network: Network = Form('offline'), confirm_browser_risk: str | None = Form(None), extensions: str | None = Form(None, description='Расширения через запятую, например .eml,.html'), persist: bool = Form(True), options: str | None = Form(None)):
        check(network, confirm_browser_risk)
        with tempfile.TemporaryDirectory(prefix='antiphish-batch-') as directory:
            path = Path(directory) / Path(file.filename or 'batch.zip').name
            path.write_bytes(upload(file))
            with lock:
                result = run_batch(path, analyzer, profile=profile, network=network, browser_confirmation=confirm_browser_risk, extensions=extensions.split(',') if extensions else None, store=store if persist else None,options=component_options(profile,options))
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

    @app.get('/reports/{identifier}/artifacts/{digest}', tags=['История'])
    def artifact(identifier: str, digest: str):
        from urllib.parse import quote
        item = store.artifact(identifier, digest)
        if not item or item['kind'] == 'learning':
            raise HTTPException(404, 'Artifact not found')
        headers = {'X-Content-Type-Options':'nosniff','Cache-Control':'no-store',
            'Content-Security-Policy':"default-src 'none'; sandbox",'Referrer-Policy':'no-referrer'}
        if item['kind'] != 'image':
            headers['Content-Disposition'] = "attachment; filename*=UTF-8''"+quote(item['name'])
        return Response(item['data'], media_type=item['media_type'], headers=headers)

    @app.get('/reviews', tags=['Образцы'])
    def reviews(limit: int = 100):
        from .reviews import list_reviews
        return {'samples':list_reviews(analyzer.kb.path,limit)}

    @app.post('/reviews', tags=['Образцы'])
    def review(request: ReviewRequest):
        from .reviews import save_review
        with lock:
            saved = store.get(request.report_id)
            if not saved:
                raise HTTPException(404,'Report not found')
            try:
                return save_review(analyzer.kb.path,saved,store.learning(request.report_id),request.label,request.comment,request.page_ids)
            except ValueError as exc:
                raise HTTPException(422,str(exc)) from exc

    @app.delete('/reviews/{identifier}', tags=['Образцы'])
    def forget_review(identifier: str):
        from .reviews import delete_review
        with lock:
            if not delete_review(analyzer.kb.path,identifier):
                raise HTTPException(404,'Sample not found')
        return {'deleted':identifier}

    @app.post('/knowledge/update-feeds', tags=['Система'])
    def refresh_feeds():
        from .reputation import update_feeds
        from .kb import initialize_empty_kb
        with lock:
            if not analyzer.kb.path.exists():
                initialize_empty_kb(analyzer.kb.path)
            return update_feeds(analyzer.kb.path.with_suffix('.reputation.sqlite'))


    @app.get('/reports/{identifier}/raw-urls',tags=['История'])
    def raw_urls(identifier: str):
        if not store.get(identifier):
            raise HTTPException(404,'Report not found')
        return {'urls':store.learning(identifier).get('urls',[]),'note':'Полные URL могут содержать личные параметры. Не открываются автоматически.'}

    @app.get('/reports/{identifier}/text',tags=['История'])
    def report_text(identifier: str,scope: str='message'):
        from .contexts import redact
        saved=store.get(identifier)
        if not saved: raise HTTPException(404,'Report not found')
        learning=store.learning(identifier)
        text=learning.get('message_text','') if scope=='message' else next((p.get('text_body','') for p in learning.get('pages',[]) if p['id']==scope),'')
        return {'text':redact(text,2_000_000),'available':bool(text),'scope':scope}

    @app.get('/knowledge/entries/{kind}',tags=['База знаний'])
    def entries(kind: str,q: str='',offset: int=0,limit: int=50):
        from .knowledge import browse
        try:
            with lock: return browse(analyzer.kb.path,kind,q,offset,limit)
        except ValueError as exc: raise HTTPException(422,str(exc)) from exc

    @app.delete('/knowledge/entries/{kind}/{identifier}',tags=['База знаний'])
    def delete_entry(kind: str,identifier: int):
        from .knowledge import mutate
        try:
            with lock: return mutate(analyzer.kb.path,kind,identifier,delete=True)
        except LookupError as exc: raise HTTPException(404,str(exc)) from exc
        except ValueError as exc: raise HTTPException(422,str(exc)) from exc

    @app.get('/knowledge/entries/{kind}/{identifier}',tags=['База знаний'])
    def inspect_knowledge(kind: str,identifier: int):
        from .knowledge import inspect_entry
        try:
            with lock: return inspect_entry(analyzer.kb.path,kind,identifier)
        except LookupError as exc: raise HTTPException(404,str(exc)) from exc
        except ValueError as exc: raise HTTPException(422,str(exc)) from exc

    @app.patch('/knowledge/entries/{kind}/{identifier}',tags=['База знаний'])
    def label_entry(kind: str,identifier: int,request: EntryLabel):
        from .knowledge import mutate
        try:
            with lock: return mutate(analyzer.kb.path,kind,identifier,label=request.label)
        except LookupError as exc: raise HTTPException(404,str(exc)) from exc
        except ValueError as exc: raise HTTPException(422,str(exc)) from exc

    @app.post('/knowledge/undo/{identifier}',tags=['База знаний'])
    def undo_entry(identifier: str):
        from .knowledge import undo
        try:
            with lock: return undo(analyzer.kb.path,identifier)
        except LookupError as exc: raise HTTPException(404,str(exc)) from exc
        except (ValueError,sqlite3.IntegrityError) as exc: raise HTTPException(409,str(exc)) from exc

    @app.post('/knowledge/entries/{kind}',tags=['База знаний'])
    def add_entry(kind: str,request: Indicator):
        from .knowledge import add_indicator
        try:
            with lock: return add_indicator(analyzer.kb.path,kind,request.value,request.source)
        except ValueError as exc: raise HTTPException(422,str(exc)) from exc
        except sqlite3.IntegrityError as exc: raise HTTPException(409,'Такая запись уже существует') from exc

    @app.post('/knowledge/import-file',tags=['База знаний'])
    def import_review(file: UploadFile=File(...),label: Literal['phishing','benign']=Form(...),comment: str=Form(''),learn_forms: bool=Form(False)):
        from .reviews import save_review
        with lock:
            report=analyzer.analyze(upload(file),name=Path(file.filename).name,profile='custom',network='offline',options={'ocr':False,'qr':False,'llm':False,'siglip':False,'logo_references':False})
            if report.analysis_status.value=='FAILED':
                raise HTTPException(422,'Файл не удалось разобрать: '+'; '.join(report.warnings))
            identifier=store.put(report)
            pages=[p.id for p in report.pages if p.forms and p.identity_source=='dom'] if learn_forms else []
            result=save_review(analyzer.kb.path,store.get(identifier),store.learning(identifier),label,comment,pages)
        return {**result,'report_id':identifier}

    return app


def main(open_browser: bool = False):
    import uvicorn
    host = os.environ.get('ANTIPHISH_API_HOST', '127.0.0.1')
    port = int(os.environ.get('ANTIPHISH_API_PORT', '8000'))
    if open_browser:
        import webbrowser
        visible_host = '127.0.0.1' if host in {'0.0.0.0','::'} else host
        timer = threading.Timer(1.5, lambda:webbrowser.open(f'http://{visible_host}:{port}'))
        timer.daemon = True
        timer.start()
    uvicorn.run(create_app(), host=host, port=port, workers=1)

