from pathlib import Path
import json
import os
from collections import OrderedDict
from threading import Lock
from uuid import uuid4
from hashlib import sha256
from urllib.error import URLError
from urllib.request import urlopen

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

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
    return {"status": "ok", "mode": "sample-data"}


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
    trace.extend(result.investigation)
    warnings.extend(result.ai_warnings)
    if result.ai_status != "completed":
        raise OllamaError(result.ai_error or "AI 比較未完成，唯讀證據與假說仍可查看。")
    return result.ai_analysis, trace


@app.post("/api/scan", response_model=ScanResult)
def scan_sample(request: ScanRequest) -> ScanResult:
    sample_names = request.samples if request.samples is not None else [request.sample]
    # Dedupe overlapping files so replaying the same evidence cannot inflate thresholds.
    event_index = {event.id: event for name in sample_names for event in load_sample_events(name)}
    events = sorted(event_index.values(), key=lambda event: event.timestamp)
    sample_name = ", ".join(sample_names)
    alerts = detect_ssh_alerts([e for e in events if e.source == "auth.log"])
    alerts += detect_nginx_alerts([e for e in events if e.source == "nginx.access.log"])
    for alert in alerts:
        key = alert.alert_type + "|" + "|".join(sorted(e.id for e in alert.related_events))
        alert.id = alert.id.rsplit("-", 1)[0] + "-" + sha256(key.encode()).hexdigest()[:12]
    alerts.sort(key=lambda alert: alert.timestamp, reverse=True)
    incidents = correlate_incidents(alerts)
    store = EvidenceStore(events, alerts, incidents)
    scan_id = uuid4().hex
    with SCAN_LOCK:
        SCANS[scan_id] = store
        while len(SCANS) > 32:
            SCANS.popitem(last=False)
    result = ScanResult(
        sample=sample_name,
        event_count=len(events),
        alerts=alerts,
        ai_status="skipped",
        scan_id=scan_id,
        incidents=incidents,
        focused_incident_id=priority_incident(store).id if store.incidents else None,
    )
    if request.with_ai:
        try:
            result.ai_analysis, result.investigation = analyze_security_scan(
                sample_name, store, result.investigation, result.ai_warnings, request.tool_budget
            )
            result.ai_status = "completed"
        except OllamaError as error:
            # Keep deterministic detections available if the optional local model is offline.
            result.ai_status = "unavailable"
            result.ai_error = str(error)
    result.hypotheses = list(store.hypothesis_reports.values())
    return result


def scan_store(scan_id: str) -> EvidenceStore:
    with SCAN_LOCK:
        store = SCANS.get(scan_id)
    if store is None:
        raise HTTPException(404, "掃描已不存在；重新掃描以建立證據快照")
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
            return run_hypothesis_investigation(store, incident_id, with_ai=request.with_ai,
                                               tool_budget=request.tool_budget, question_ids=request.question_ids)
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
