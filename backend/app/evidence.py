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
    "name": name, "description": "Read-only query within this scan; returns evidence IDs and truncation information.",
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
        from app.graph import build_evidence_graph
        self.graph = build_evidence_graph(self)
        from app.hypotheses import build_hypothesis_report
        from threading import Lock
        self.hypothesis_reports = {i.id: build_hypothesis_report(self, i) for i in incidents}
        self.investigation_lock = Lock()

    def execute(self, name: str, arguments: dict) -> dict:
        if name not in TOOL_REQUIREMENTS:
            raise ValueError("Investigation tool not allowed")
        if not isinstance(arguments, dict):
            raise ValueError("Arguments must be an object")
        if any(key not in TOOL_FIELDS[name] and value is not None for key, value in arguments.items()):
            raise ValueError("Tool does not support this query parameter")
        query = Query.model_validate(arguments)
        if any(getattr(query, field) is None for field in TOOL_REQUIREMENTS[name]):
            raise ValueError("Required query parameter missing")
        for bound in (query.start, query.end):
            if bound and bound.tzinfo is None:
                raise ValueError("Time bounds must include a timezone")
        if query.start and query.end and query.start > query.end:
            raise ValueError("Start time must not be after end time")
        if name == "get_incident_timeline":
            incident = next((i for i in self.incidents if i.id == query.incident_id), None)
            if incident is None:
                raise ValueError("Incident not found in this scan")
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
