from pathlib import Path
from datetime import datetime, timezone
import sqlite3
from copy import deepcopy
import json
import os
from collections import OrderedDict
from threading import Lock
from uuid import uuid4
from hashlib import sha256
from urllib.error import URLError
from urllib.request import urlopen

from fastapi import FastAPI, HTTPException, Request, Query
from starlette.datastructures import UploadFile
from starlette.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, Response, JSONResponse

from app.incidents import correlate_incidents
from app.evidence import EvidenceStore
from app.detectors.nginx import detect_nginx_alerts
from app.detectors.ssh import detect_ssh_alerts
from app.copilot import OllamaError, analyze_security_scan as legacy_analyze_security_scan
from app.investigator import run_hypothesis_investigation
from app.intelligence_models import InvestigationRequest, EvidenceGraph, HypothesisReport
from app.models import IncidentInvestigationResult
from app.models import LogEvent, ScanRequest, ScanResult, SecurityAlert
from app.parsers.nginx import parse_nginx_logs
from app.parsers.ssh import parse_ssh_logs
from app.importer import parse_import, limits
from app.storage import repository
from app.reports import incident_report


ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT
SAMPLE_YEAR = 2026
SAMPLES = {
    "scenario": {"multi_stage": "跨來源 · Web 探測 → SSH 可疑登入"},
    "ssh": {
        "compromised_login.log": "SSH · 暴力破解與可疑登入",
        "normal.log": "SSH · 一般登入",
        "bruteforce.log": "SSH · 暴力破解",
        "suspicious_login.log": "SSH · 多次失敗後登入成功",
    },
    "nginx": {
        "normal.log": "Nginx · 一般流量",
        "sqli.log": "Nginx · SQL Injection",
        "xss.log": "Nginx · XSS",
        "enumeration.log": "Nginx · 路徑列舉",
        "mix.log": "Nginx · 混合攻擊情境",
    },
}

SCANS: OrderedDict[str, EvidenceStore] = OrderedDict()
SCAN_LOCK = Lock()

app = FastAPI(
    title="AI Security Log Copilot API",
    description="Local SSH/Nginx detection, incident correlation and read-only investigation.",
    version="0.1.0",
)


def load_sample_events(sample: str = "ssh:compromised_login.log") -> list[LogEvent]:
    try:
        source, filename = sample.split(":", maxsplit=1)
    except ValueError as error:
        raise HTTPException(status_code=404, detail="樣本名稱格式應為 source:filename") from error
    if source not in SAMPLES or filename not in SAMPLES[source]:
        raise HTTPException(status_code=404, detail="找不到指定的樣本")
    if source == "scenario":
        directory = ROOT / "samples" / "scenarios"
        return sorted(parse_nginx_logs((directory / "multi_stage_access.log").read_text())
                      + parse_ssh_logs((directory / "multi_stage_auth.log").read_text(), year=SAMPLE_YEAR),
                      key=lambda event: event.timestamp)
    sample_dir = ROOT / "samples" / "ssh" if source == "ssh" else ROOT / "samples"
    sample_path = sample_dir / filename
    text = sample_path.read_text(encoding="utf-8")
    if source == "ssh":
        return parse_ssh_logs(text, year=SAMPLE_YEAR)
    return parse_nginx_logs(text)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-mvp"}


@app.get("/api/events", response_model=list[LogEvent])
def get_events() -> list[LogEvent]:
    return load_sample_events()


@app.get("/api/alerts", response_model=list[SecurityAlert])
def get_alerts() -> list[SecurityAlert]:
    return detect_ssh_alerts(load_sample_events())


@app.get("/api/samples")
def get_samples() -> list[dict[str, str]]:
    return [
        {"name": f"{source}:{name}", "label": label, "source": source}
        for source, samples in SAMPLES.items()
        for name, label in samples.items()
    ]


def priority_incident(store):
    ranks = {"Critical": 3, "High": 2, "Medium": 1}
    return max(store.incidents, key=lambda i: (ranks.get(i.severity, 0), i.end_time), default=None)


def analyze_security_scan(sample_name, store, trace, warnings, tool_budget=4):
    incident = priority_incident(store)
    if incident is None:
        return legacy_analyze_security_scan(sample_name, store, trace, warnings)
    with store.investigation_lock:
        result = run_hypothesis_investigation(store, incident.id, with_ai=True, tool_budget=tool_budget)
    store.result.investigation_results[incident.id] = result
    trace.extend(result.investigation)
    warnings.extend(result.ai_warnings)
    if result.ai_status != "completed":
        raise OllamaError(result.ai_error or "AI 比較未完成，唯讀證據與假說仍可查看。")
    return result.ai_analysis, trace


@app.post("/api/scan", response_model=ScanResult)
def scan_sample(request: ScanRequest) -> ScanResult:
    sample_names = request.samples if request.samples is not None else [request.sample]
    events = [event for name in sample_names for event in load_sample_events(name)]
    return create_scan(events, ", ".join(sample_names), request.with_ai, request.tool_budget)


def create_scan(input_events, label, with_ai=False, tool_budget=4, file_results=None):
    # Dedupe overlapping evidence; duplicates cannot inflate detector thresholds.
    event_index = {event.id: event for event in input_events}
    events = sorted(event_index.values(), key=lambda event: (event.timestamp, event.id))
    alerts = detect_ssh_alerts([e for e in events if e.source == "auth.log"])
    alerts += detect_nginx_alerts([e for e in events if e.source == "nginx.access.log"])
    for alert in alerts:
        key = alert.alert_type + "|" + "|".join(sorted(e.id for e in alert.related_events))
        alert.id = alert.id.rsplit("-", 1)[0] + "-" + sha256(key.encode()).hexdigest()[:12]
    alerts.sort(key=lambda alert: alert.timestamp, reverse=True)
    incidents = correlate_incidents(alerts)
    store = EvidenceStore(events, alerts, incidents)
    result = ScanResult(
        sample=label, event_count=len(events), alerts=alerts, ai_status="skipped",
        scan_id=uuid4().hex, incidents=incidents,
        focused_incident_id=priority_incident(store).id if store.incidents else None,
        created_at=datetime.now(timezone.utc),
        source_types=sorted({"ssh" if e.source == "auth.log" else "nginx" for e in events}),
        file_results=file_results or [], duplicate_event_count=len(input_events)-len(events)+sum(r["duplicate_lines"] for r in file_results or []),
    )
    store.result = result
    if with_ai:
        try:
            result.ai_analysis, result.investigation = analyze_security_scan(
                label, store, result.investigation, result.ai_warnings, tool_budget)
            result.ai_status = "completed"
        except OllamaError as error:
            result.ai_status = "unavailable"
            result.ai_error = str(error)
    result.hypotheses = list(store.hypothesis_reports.values())
    # Publish only after one transactional write commits successfully.
    with SCAN_LOCK:
        persist(store)
        cache_store(result.scan_id, store)
    return result


def persist(store):
    try:
        repository.save(store)
    except LookupError as error:
        raise HTTPException(404, "掃描已被刪除。") from error
    except (sqlite3.Error, OSError) as error:
        raise HTTPException(503, "本機資料庫寫入失敗；本次結果未完成儲存，請確認資料目錄可寫及磁碟空間。") from error


def cache_store(scan_id, store):
    SCANS[scan_id] = store
    while len(SCANS) > 32:
        candidate = next((key for key, value in SCANS.items()
                          if key != scan_id and not value.investigation_lock.locked()), None)
        if candidate is None:
            break
        SCANS.pop(candidate)


class UploadTooLarge(Exception):
    pass


class UploadLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['path'] != '/api/scans/upload':
            return await self.app(scope, receive, send)
        ceiling = limits()['max_total_bytes'] + 65536
        headers = dict(scope.get('headers', []))
        try:
            declared = int(headers.get(b'content-length', b'0'))
        except ValueError:
            declared = 0
        if declared > ceiling:
            return await JSONResponse({'detail': '上傳內容超過總大小上限。'}, 413)(scope, receive, send)
        consumed = 0

        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            consumed += len(message.get('body', b''))
            if consumed > ceiling:
                raise UploadTooLarge()
            return message
        try:
            await self.app(scope, bounded_receive, send)
        except UploadTooLarge:
            await JSONResponse({'detail': '上傳內容超過總大小上限。'}, 413)(scope, receive, send)


app.add_middleware(UploadLimitMiddleware)


@app.get('/api/import/config')
def import_config():
    return {**limits(), 'source_types': ['ssh', 'nginx'],
            'ssh_year': datetime.now().year, 'ssh_timezone': os.getenv('LOG_TIMEZONE', 'Asia/Taipei')}


@app.post('/api/scans/upload', response_model=ScanResult, openapi_extra={
    'requestBody': {'required': True, 'content': {'multipart/form-data': {'schema': {
        'type': 'object', 'required': ['files', 'source_types'], 'properties': {
            'files': {'type': 'array', 'items': {'type': 'string', 'format': 'binary'}},
            'source_types': {'type': 'array', 'items': {'type': 'string', 'enum': ['ssh', 'nginx']}},
            'ssh_year': {'type': 'integer', 'minimum': 1970, 'maximum': 9999},
            'with_ai': {'type': 'boolean', 'default': False},
            'tool_budget': {'type': 'integer', 'minimum': 0, 'maximum': 12, 'default': 4},
        }}}}}})
async def upload_scan(request: Request):
    config = limits()
    try:
        async with request.form(max_files=config['max_files'], max_fields=32, max_part_size=4096) as form:
            files, sources = form.getlist('files'), form.getlist('source_types')
            if not files or len(files) != len(sources) or any(not isinstance(f, UploadFile) for f in files):
                raise HTTPException(422, '請提供 files 與逐檔對應的 source_types。')
            if any(source not in ('ssh', 'nginx') for source in sources):
                raise HTTPException(422, '不支援的日誌類型；僅接受 ssh 或 nginx。')
            try:
                year = int(form.get('ssh_year', datetime.now().year))
                budget = int(form.get('tool_budget', 4))
                if not 1970 <= year <= 9999 or not 0 <= budget <= 12:
                    raise ValueError()
                ai_value = str(form.get('with_ai', 'false')).lower()
                if ai_value not in ('true', 'false'):
                    raise ValueError()
            except (ValueError, TypeError):
                raise HTTPException(422, 'ssh_year 必須介於 1970–9999、tool_budget 介於 0–12、with_ai 為 true/false。')
            events, reports, total = [], [], 0
            for file, source in zip(files, sources):
                data = await file.read(config['max_file_bytes'] + 1)
                total += len(data)
                if len(data) > config['max_file_bytes'] or total > config['max_total_bytes']:
                    raise HTTPException(413, '檔案超過單檔或總大小上限。')
                try:
                    parsed, report = await run_in_threadpool(parse_import, data, file.filename, source, ssh_year=year)
                except ValueError as error:
                    raise HTTPException(413, str(error)) from error
                events.extend(parsed)
                reports.append(report)
            if not events:
                raise HTTPException(422, {'message': '沒有可解析的事件；請檢查格式、編碼與日誌類型。', 'file_results': reports})
            return await run_in_threadpool(create_scan, events, '本機匯入：' + ', '.join(r['filename'] for r in reports),
                                           ai_value == 'true', budget, reports)
    except UploadTooLarge:
        raise HTTPException(413, '上傳內容超過總大小上限。')


@app.get('/api/scans')
def scan_history(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    try:
        return repository.history(limit, offset)
    except (sqlite3.Error, OSError) as error:
        raise HTTPException(503, '無法讀取本機掃描歷史。') from error


@app.get('/api/scans/{scan_id}', response_model=ScanResult)
def get_scan(scan_id: str):
    store = scan_store(scan_id)
    with store.investigation_lock:
        return store.result.model_copy(update={'hypotheses': list(store.hypothesis_reports.values())})


@app.delete('/api/scans/{scan_id}')
def delete_scan(scan_id: str):
    with SCAN_LOCK:
        try:
            deleted = repository.delete(scan_id)
        except (sqlite3.Error, OSError) as error:
            raise HTTPException(503, '刪除失敗；請確認本機資料庫可寫。') from error
        store = SCANS.pop(scan_id, None)
        if store is not None:
            store.deleted = True
    if not deleted:
        raise HTTPException(404, '找不到指定掃描。')
    return {'deleted': True, 'scan_id': scan_id}


def scan_store(scan_id: str) -> EvidenceStore:
    with SCAN_LOCK:
        store = SCANS.get(scan_id)
        if store is None:
            try:
                store = repository.load(scan_id)
            except (sqlite3.Error, OSError, ValueError) as error:
                raise HTTPException(503, "無法載入本機掃描快照。") from error
            if store is not None:
                cache_store(scan_id, store)
    if store is None:
        raise HTTPException(404, "找不到掃描；可能已被刪除。")
    return store


@app.get("/api/scans/{scan_id}/hypotheses", response_model=list[HypothesisReport])
def get_hypotheses(scan_id: str):
    return list(scan_store(scan_id).hypothesis_reports.values())


@app.post("/api/scans/{scan_id}/incidents/{incident_id}/investigate", response_model=IncidentInvestigationResult)
def investigate_incident(scan_id: str, incident_id: str, request: InvestigationRequest):
    store = scan_store(scan_id)
    if incident_id not in store.hypothesis_reports:
        raise HTTPException(404, "找不到本次掃描的 Incident")
    try:
        with store.investigation_lock:
            previous = deepcopy(store.hypothesis_reports)
            previous_result = store.result.model_copy(deep=True)
            result = run_hypothesis_investigation(store, incident_id, with_ai=request.with_ai,
                                                  tool_budget=request.tool_budget, question_ids=request.question_ids)
            saved = result.model_copy(deep=True)
            old = store.result.investigation_results.get(incident_id)
            if saved.ai_analysis is None and old is not None:
                saved.ai_analysis = old.ai_analysis
                saved.investigation = old.investigation + saved.investigation
            store.result.investigation_results[incident_id] = saved
            try:
                with SCAN_LOCK:
                    if getattr(store, 'deleted', False):
                        raise HTTPException(404, '掃描已被刪除。')
                    persist(store)
            except HTTPException:
                store.hypothesis_reports = previous
                store.result = previous_result
                raise
            return result
    except ValueError as error:
        raise HTTPException(422, str(error)) from error


@app.get("/api/scans/{scan_id}/graph", response_model=EvidenceGraph)
def get_graph(scan_id: str):
    return scan_store(scan_id).graph


@app.get("/api/scans/{scan_id}/evidence/{evidence_id}")
def get_evidence(scan_id: str, evidence_id: str):
    store = scan_store(scan_id)
    for items in (store.events, store.alerts, store.incidents):
        for item in items:
            if item.id == evidence_id:
                return item
    raise HTTPException(404, "找不到本次掃描的證據")


@app.get("/api/scans/{scan_id}/tools/{tool_name}")
def investigate(scan_id: str, tool_name: str, source_ip: str | None = None,
                username: str | None = None, start: str | None = None, end: str | None = None,
                incident_id: str | None = None, limit: int = 40):
    try:
        return scan_store(scan_id).execute(tool_name, dict(source_ip=source_ip, username=username,
                      start=start, end=end, incident_id=incident_id, limit=limit))
    except ValueError as error:
        raise HTTPException(422, "調查參數無效或工具不允許") from error


@app.get("/api/ollama/status")
def ollama_status() -> dict[str, str | bool]:
    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "qwen3:4b")
    try:
        with urlopen(f"{base_url}/api/tags", timeout=2) as response:
            installed = [item.get("name", "") for item in json.load(response).get("models", [])]
        model_available = any(name == model or name.startswith(f"{model}:") for name in installed)
        return {
            "available": model_available,
            "model": model,
            "message": "模型已就緒" if model_available else "Ollama 已啟動，但找不到指定模型",
        }
    except (URLError, TimeoutError, json.JSONDecodeError):
        return {"available": False, "model": model, "message": "無法連線本機 Ollama"}


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


# Serve only public assets; mounting the repository exposed source and local config.
@app.get("/app.js", include_in_schema=False)
def javascript() -> FileResponse:
    return FileResponse(FRONTEND / "app.js", media_type="application/javascript")


@app.get("/styles.css", include_in_schema=False)
def stylesheet() -> FileResponse:
    return FileResponse(FRONTEND / "styles.css", media_type="text/css")


@app.get("/graph.js", include_in_schema=False)
def graph_javascript() -> FileResponse:
    return FileResponse(FRONTEND / "graph.js", media_type="application/javascript")


@app.get("/hypotheses.js", include_in_schema=False)
def hypotheses_javascript() -> FileResponse:
    return FileResponse(FRONTEND / "hypotheses.js", media_type="application/javascript")


@app.get('/api/scans/{scan_id}/incidents/{incident_id}/report.md')
def download_report(scan_id: str, incident_id: str):
    store = scan_store(scan_id)
    try:
        with store.investigation_lock:
            content = incident_report(store, incident_id)
    except ValueError as error:
        raise HTTPException(404, str(error)) from error
    # IDs are generated by the backend, never uploaded filenames.
    filename = 'incident-' + sha256(incident_id.encode()).hexdigest()[:12] + '.md'
    return Response(content, media_type='text/markdown; charset=utf-8',
                    headers={'Content-Disposition': f'attachment; filename="{filename}"'})
