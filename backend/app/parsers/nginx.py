import re
from datetime import datetime

from app.models import LogEvent


ACCESS_LOG_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"(?:\s+.*)?$'
)
REQUEST_LINE = re.compile(r"^(?P<method>\S+)\s+(?P<target>\S+)\s+(?P<protocol>HTTP/\S+)$")


def parse_nginx_line(line: str) -> LogEvent | None:
    """Parse an Nginx combined access log entry into a normalized event."""
    match = ACCESS_LOG_LINE.match(line.strip())
    if not match:
        return None
    request = REQUEST_LINE.match(match.group("request"))
    if not request:
        return None
    try:
        timestamp = datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z")
        byte_count = int(match.group("bytes")) if match.group("bytes").isdigit() else None
    except ValueError:
        return None

    return LogEvent(
        timestamp=timestamp,
        source="nginx.access.log",
        event_type="http_request",
        source_ip=match.group("ip"),
        request_method=request.group("method"),
        request_target=request.group("target"),
        status_code=int(match.group("status")),
        user_agent=match.group("agent"),
        metadata={"bytes_sent": byte_count, "referer": match.group("referer")},
        raw_log=line.strip(),
    )


def parse_nginx_logs(text: str) -> list[LogEvent]:
    events = [event for line in text.splitlines() if (event := parse_nginx_line(line))]
    return sorted(events, key=lambda event: event.timestamp)
