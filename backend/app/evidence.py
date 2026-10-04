"""Read-only, scan-scoped investigation. No shell, file paths, or external queries."""
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from app.models import Incident, LogEvent, SecurityAlert


class Query(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_ip: str | None = Field(default=None, max_length=100)
    username: str | None = Field(default=None, max_length=100)
    start: datetime | None = None
    end: datetime | None = None
    incident_id: str | None = Field(default=None, max_length=100)
    limit: int = Field(default=40, ge=1, le=100)


TOOL_REQUIREMENTS = {
    "search_events": [], "get_user_logins": ["username"],
    "get_related_alerts": ["source_ip"], "get_incident_timeline": ["incident_id"],
}
TOOL_FIELDS = {
    "search_events": {"source_ip", "username", "start", "end", "limit"},
    "get_user_logins": {"username", "source_ip", "start", "end", "limit"},
    "get_related_alerts": {"source_ip", "start", "end", "limit"},
    "get_incident_timeline": {"incident_id", "limit"},
}
TOOLS = [{"type": "function", "function": {
    "name": name, "description": "唯讀查詢本次掃描資料；回傳有 ID 的證據與截斷資訊。",
    "parameters": {"type": "object", "additionalProperties": False,
                   "properties": {key: {k: v for k, v in value.items() if k not in {"title", "default"}}
                                  for key, value in Query.model_json_schema()["properties"].items()
                                  if key in TOOL_FIELDS[name]}, "required": required},
}} for name, required in TOOL_REQUIREMENTS.items()]


class EvidenceStore:
    def __init__(self, events: list[LogEvent], alerts: list[SecurityAlert], incidents: list[Incident]):
        self.events = tuple(events)
        self.alerts = tuple(alerts)
        self.incidents = tuple(incidents)
        self.ids = {item.id for items in (events, alerts, incidents) for item in items}

    def execute(self, name: str, arguments: dict) -> dict:
        if name not in TOOL_REQUIREMENTS:
            raise ValueError("不允許的調查工具")
        if not isinstance(arguments, dict):
            raise ValueError("參數必須是物件")
        if any(key not in TOOL_FIELDS[name] and value is not None for key, value in arguments.items()):
            raise ValueError("工具不支援此查詢參數")
        query = Query.model_validate(arguments)
        if any(getattr(query, field) is None for field in TOOL_REQUIREMENTS[name]):
            raise ValueError("缺少必要查詢參數")
        for bound in (query.start, query.end):
            if bound and bound.tzinfo is None:
                raise ValueError("時間範圍必須包含時區")
        if query.start and query.end and query.start > query.end:
            raise ValueError("開始時間不可晚於結束時間")
        if name == "get_incident_timeline":
            incident = next((i for i in self.incidents if i.id == query.incident_id), None)
            if incident is None:
                raise ValueError("找不到本次掃描的 Incident")
            items = [t.model_dump(mode="json") for t in incident.timeline]
        else:
            source = self.alerts if name == "get_related_alerts" else self.events
            filtered = [item for item in source
                        if (query.source_ip is None or item.source_ip == query.source_ip)
                        and (query.username is None or item.username == query.username)
                        and (query.start is None or item.timestamp >= query.start)
                        and (query.end is None or item.timestamp <= query.end)
                        and (name != "get_user_logins" or item.event_type == "authentication_success")]
            items = [item.model_dump(mode="json", exclude_none=True, exclude={"raw_log", "related_events", "metadata", "user_agent"}) for item in filtered]
        return {"items": items[:query.limit], "total": len(items), "truncated": len(items) > query.limit,
                "scope": "current_scan_only"}
