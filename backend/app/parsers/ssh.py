import re
from datetime import datetime

from app.models import LogEvent


SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)
FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port"
)
ACCEPTED_AUTH = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port"
)


def parse_ssh_line(line: str, *, year: int | None = None) -> LogEvent | None:
    """Parse a common OpenSSH auth.log line; return None for unrelated lines."""
    match = SYSLOG_PREFIX.match(line.strip())
    if not match:
        return None

    message = match.group("message")
    failed = FAILED_PASSWORD.search(message)
    accepted = ACCEPTED_AUTH.search(message)
    auth = failed or accepted
    if auth is None:
        return None

    timestamp = datetime.strptime(
        f"{year or datetime.now().year} {match.group('month')} {match.group('day')} {match.group('time')}",
        "%Y %b %d %H:%M:%S",
    )
    return LogEvent(
        timestamp=timestamp,
        event_type="authentication_failed" if failed else "authentication_success",
        source_ip=auth.group("ip"),
        username=auth.group("user"),
        raw_log=line.strip(),
    )


def parse_ssh_logs(text: str, *, year: int | None = None) -> list[LogEvent]:
    events = [event for line in text.splitlines() if (event := parse_ssh_line(line, year=year))]
    return sorted(events, key=lambda event: event.timestamp)
