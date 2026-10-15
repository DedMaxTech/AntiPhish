from pathlib import Path
import io
import json
import zipfile

import pytest

from antiphish.analyzer import Analyzer
from antiphish.batch import run_batch
from antiphish.config import Limits
from antiphish.store import ReportStore

MAIL = b'From: user@example.com\nSubject: Team meeting\n\nMeeting at ten.'


def test_batch_identifies_duplicates_and_resumes(tmp_path, empty_kb):
    folder = tmp_path / 'mail'; folder.mkdir()
    (folder/'a.eml').write_bytes(MAIL); (folder/'b.eml').write_bytes(MAIL)
    (folder/'README.md').write_text('Skip metadata')
    output = tmp_path/'result.json'
    first = run_batch(folder, Analyzer(empty_kb), output=output)
    assert first['statistics']['items'] == 2
    assert first['statistics']['duplicates_reused'] == 1
    assert len({r['id'] for r in first['results']}) == 2
    second = run_batch(folder, Analyzer(empty_kb), output=output, resume=True)
    assert second['statistics']['resumed'] == 2
    (folder/'a.eml').write_bytes(MAIL + b'Changed.')
    third = run_batch(folder, Analyzer(empty_kb), output=output, resume=True)
    assert third['statistics']['resumed'] == 1


def test_archive_no_path_traversal_and_member_limit(tmp_path, empty_kb):
    path = tmp_path/'input.zip'
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr('../outside.eml', MAIL); z.writestr('ok.eml', MAIL)
    report = run_batch(path, Analyzer(empty_kb))
    assert report['statistics']['analysis_statuses'] == {'FAILED': 1, 'COMPLETE': 1}
    assert not (tmp_path/'outside.eml').exists()
    limited = run_batch(path, Analyzer(empty_kb, Limits(max_archive_entries=1)))
    assert limited['batch_status'] == 'PARTIAL'
    assert limited['statistics']['items'] == 0


def test_resume_invalidated_by_runtime_configuration(tmp_path, empty_kb):
    folder=tmp_path/'inputs'; folder.mkdir(); (folder/'a.eml').write_bytes(MAIL)
    output=tmp_path/'results.json'
    run_batch(folder, Analyzer(empty_kb), output=output)
    result=run_batch(folder, Analyzer(empty_kb), output=output, resume=True, profile='fast')
    assert result['statistics']['resumed'] == 0


def test_api_upload_batch_history_and_confirmation(tmp_path, empty_kb):
    pytest.importorskip('fastapi')
    from fastapi.testclient import TestClient
    from antiphish.api import create_app
    client=TestClient(create_app(empty_kb,tmp_path/'history.sqlite'))
    assert client.get('/openapi.json').status_code == 200
    single=client.post('/analyze/file', files={'file':('a.eml',MAIL)}).json()
    assert single['report']['verdict'] == 'NOT_DETECTED'
    assert client.get('/reports/'+single['report_id']).json()['report'] == single['report']
    assert client.get('/reports/missing').status_code == 404
    assert client.post('/analyze',json={'source':'https://example.com','network':'browser'}).status_code == 422
    blob=io.BytesIO()
    with zipfile.ZipFile(blob,'w') as z:
        z.writestr('a.eml',MAIL); z.writestr('b.eml',MAIL)
    batch=client.post('/batch/file',files={'file':('batch.zip',blob.getvalue())}).json()
    assert batch['statistics']['items'] == 2
    assert len(client.get('/reports').json()['reports']) == 3


def test_api_rejects_chunked_body_before_multipart_spooling(tmp_path, empty_kb):
    pytest.importorskip('fastapi')
    from fastapi.testclient import TestClient
    from antiphish.api import create_app, BodyLimit
    app=create_app(empty_kb,tmp_path/'history.sqlite')
    app.user_middleware[0].kwargs['limit']=512
    client=TestClient(app)
    chunks=iter([b'--test\r\nContent-Disposition: form-data; name="file"; filename="a.eml"\r\n\r\n',b'x'*1024,b'\r\n--test--\r\n'])
    response=client.post('/analyze/file',content=chunks,headers={'Content-Type':'multipart/form-data; boundary=test'})
    assert response.status_code == 413

