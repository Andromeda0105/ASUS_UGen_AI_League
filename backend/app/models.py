from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"


class AlertStatus(StrEnum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"


class LogEvent(BaseModel):
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


class ScanRequest(BaseModel):
    sample: str = Field(min_length=1, max_length=80)
    with_ai: bool = True


class ScanResult(BaseModel):
    sample: str
    event_count: int
    alerts: list[SecurityAlert]
    ai_status: str
    ai_analysis: str | None = None
    ai_error: str | None = None
