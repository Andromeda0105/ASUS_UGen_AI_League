from pathlib import Path
import json
import os
from urllib.error import URLError
from urllib.request import urlopen

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.detectors.nginx import detect_nginx_alerts
from app.detectors.ssh import detect_ssh_alerts
from app.copilot import OllamaError, analyze_security_scan
from app.models import LogEvent, ScanRequest, ScanResult, SecurityAlert
from app.parsers.nginx import parse_nginx_logs
from app.parsers.ssh import parse_ssh_logs


ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT
SAMPLE_YEAR = 2026
SAMPLES = {
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

app = FastAPI(
    title="AI Security Log Copilot API",
    description="Deterministic SSH log parsing and alert detection prototype.",
    version="0.1.0",
)


def load_sample_events(sample: str = "ssh:compromised_login.log") -> list[LogEvent]:
    try:
        source, filename = sample.split(":", maxsplit=1)
    except ValueError as error:
        raise HTTPException(status_code=404, detail="樣本名稱格式應為 source:filename") from error
    if source not in SAMPLES or filename not in SAMPLES[source]:
        raise HTTPException(status_code=404, detail="找不到指定的樣本")
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


@app.post("/api/scan", response_model=ScanResult)
def scan_sample(request: ScanRequest) -> ScanResult:
    events = load_sample_events(request.sample)
    source = request.sample.split(":", maxsplit=1)[0]
    alerts = detect_ssh_alerts(events) if source == "ssh" else detect_nginx_alerts(events)
    result = ScanResult(
        sample=request.sample,
        event_count=len(events),
        alerts=alerts,
        ai_status="skipped",
    )
    if request.with_ai:
        try:
            result.ai_analysis = analyze_security_scan(request.sample, events, alerts)
            result.ai_status = "completed"
        except OllamaError as error:
            # Keep deterministic detections available if the optional local model is offline.
            result.ai_status = "unavailable"
            result.ai_error = str(error)
    return result


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


app.mount("/", StaticFiles(directory=FRONTEND), name="frontend")
