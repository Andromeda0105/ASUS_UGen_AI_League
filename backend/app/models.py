from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, ConfigDict, model_validator
from hashlib import sha256
from zoneinfo import ZoneInfo
import os
from app.intelligence_models import HypothesisReport, HypothesisEvaluation


class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"


class AlertStatus(StrEnum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"


class LogEvent(BaseModel):
    id: str = ""
    timestamp: datetime
    source: str = "auth.log"
    event_type: str
    source_ip: str
    username: str | None = None
    request_method: str | None = None
    request_target: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    raw_log: str

    @model_validator(mode="after")
    def normalize_identity(self):
        # Syslog has no offset; its configured host timezone must match deployment.
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=ZoneInfo(os.getenv("LOG_TIMEZONE", "Asia/Taipei")))
        if not self.id:
            key = f"{self.source}|{self.timestamp.isoformat()}|{self.raw_log}"
            self.id = "EVT-" + sha256(key.encode()).hexdigest()[:16]
        return self


class SecurityAlert(BaseModel):
    id: str
    timestamp: datetime
    alert_type: str
    title: str
    severity: Severity
    source_ip: str
    username: str | None = None
    evidence: list[str] = Field(default_factory=list)
    related_events: list[LogEvent] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.OPEN
    summary: str
    recommendation: str


class TimelineEntry(BaseModel):
    timestamp: datetime
    stage: str
    alert_id: str
    event_ids: list[str]


class Incident(BaseModel):
    id: str
    title: str
    severity: Severity
    source_ips: list[str]
    usernames: list[str]
    alert_ids: list[str]
    start_time: datetime
    end_time: datetime
    attack_stages: list[str]
    correlation_reason: str
    timeline: list[TimelineEntry]


class EvidenceClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=1500)
    evidence_ids: list[str] = Field(min_length=1, max_length=12)


class AIAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=2000)
    assessment: list[EvidenceClaim] = Field(max_length=6)
    recommendations: list[EvidenceClaim] = Field(max_length=6)
    missing_evidence: list[str] = Field(max_length=6)
    confidence: float = Field(ge=0, le=1)
    hypothesis_evaluations: list[HypothesisEvaluation] = Field(default_factory=list, max_length=3)


class ScanRequest(BaseModel):
    sample: str = Field(default="scenario:multi_stage", min_length=1, max_length=80)
    samples: list[str] | None = Field(default=None, min_length=1, max_length=16)
    with_ai: bool = True
    tool_budget: int = Field(default=4, ge=0, le=12)


class ScanResult(BaseModel):
    sample: str
    event_count: int
    alerts: list[SecurityAlert]
    ai_status: str
    scan_id: str = ""
    incidents: list[Incident] = Field(default_factory=list)
    investigation: list[dict] = Field(default_factory=list)
    ai_analysis: AIAnalysis | None = None
    ai_error: str | None = None
    ai_warnings: list[str] = Field(default_factory=list)
    hypotheses: list[HypothesisReport] = Field(default_factory=list)
    focused_incident_id: str | None = None


class IncidentInvestigationResult(BaseModel):
    incident_id: str
    report: HypothesisReport
    ai_status: str = "skipped"
    ai_analysis: AIAnalysis | None = None
    ai_error: str | None = None
    ai_warnings: list[str] = Field(default_factory=list)
    investigation: list[dict] = Field(default_factory=list)
