import re
from collections import defaultdict
from datetime import timedelta
from html import unescape
from urllib.parse import unquote_plus, urlsplit

from app.models import LogEvent, SecurityAlert, Severity


def _decoded_target(event: LogEvent) -> str:
    value = event.request_target or ""
    for _ in range(3):
        decoded = unescape(unquote_plus(value))
        if decoded == value:
            break
        value = decoded
    return value


SQLI_PATTERNS = [
    ("UNION SELECT", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)),
    ("OR/AND boolean tautology", re.compile(r"\b(?:or|and)\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1\b", re.IGNORECASE)),
    ("time-delay function", re.compile(r"\b(?:sleep|benchmark|pg_sleep)\s*\(", re.IGNORECASE)),
    ("information_schema reference", re.compile(r"\binformation_schema\b", re.IGNORECASE)),
    ("destructive SQL statement", re.compile(r"\b(?:drop|truncate)\s+(?:table|database)\b", re.IGNORECASE)),
    ("SQL comment marker", re.compile(r"['\"]\s*(?:--|/\*|#)", re.IGNORECASE)),
]

XSS_PATTERNS = [
    ("script tag", re.compile(r"<\s*script\b", re.IGNORECASE)),
    ("inline event handler", re.compile(r"\bon(?:error|load|click|mouseover)\s*=", re.IGNORECASE)),
    ("javascript URL", re.compile(r"javascript\s*:", re.IGNORECASE)),
]

ENUMERATION_PATHS = [
    re.compile(r"(?:^|/)\.env(?:\.|/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)\.git(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:wp-admin|wp-login\.php|phpmyadmin|admin|administrator)(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:backup|dump|database|db)(?:[-_.][^/]*)?\.(?:zip|tar|gz|sql|bak)(?:$|/)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:server-status|actuator/env)(?:/|$)", re.IGNORECASE),
]


class SQLiDetector:
    """Stateless request-pattern detector for SQL injection attempts."""

    def detect(self, events: list[LogEvent]) -> list[SecurityAlert]:
        alerts = []
        for event in events:
            target = _decoded_target(event)
            matches = [label for label, pattern in SQLI_PATTERNS if pattern.search(target)]
            if not matches:
                continue
            alerts.append(
                SecurityAlert(
                    id=f"NGX-SQLI-{len(alerts) + 1:04d}",
                    timestamp=event.timestamp,
                    alert_type="sqli_attempt",
                    title="SQL Injection 攻擊嘗試",
                    severity=Severity.HIGH,
                    source_ip=event.source_ip,
                    evidence=[f"請求路徑包含可疑 SQL 特徵：{', '.join(matches[:3])}", f"HTTP {event.status_code}"],
                    related_events=[event],
                    summary="Nginx 請求參數符合常見 SQL Injection 特徵。這代表攻擊嘗試；單憑 access log 無法確認應用程式是否成功遭利用。",
                    recommendation="檢查對應應用程式路由是否使用參數化查詢，並比對該請求的應用程式及資料庫日誌。",
                )
            )
        return alerts


class XSSDetector:
    """Stateless request-pattern detector for reflected/stored XSS attempts."""

    def detect(self, events: list[LogEvent]) -> list[SecurityAlert]:
        alerts = []
        for event in events:
            target = _decoded_target(event)
            matches = [label for label, pattern in XSS_PATTERNS if pattern.search(target)]
            if not matches:
                continue
            alerts.append(
                SecurityAlert(
                    id=f"NGX-XSS-{len(alerts) + 1:04d}",
                    timestamp=event.timestamp,
                    alert_type="xss_attempt",
                    title="XSS 攻擊嘗試",
                    severity=Severity.HIGH,
                    source_ip=event.source_ip,
                    evidence=[f"請求路徑包含可疑 XSS 特徵：{', '.join(matches[:3])}", f"HTTP {event.status_code}"],
                    related_events=[event],
                    summary="Nginx 請求參數包含可疑 HTML 或 JavaScript 片段。這代表攻擊嘗試，不代表腳本已在使用者瀏覽器執行。",
                    recommendation="檢查相關頁面是否對輸出內容做適當編碼，並確認 Content Security Policy 與應用程式日誌。",
                )
            )
        return alerts


class EnumerationDetector:
    """Stateful per-scan detector grouping sensitive path probes by source IP."""

    def __init__(
        self,
        *,
        window: timedelta = timedelta(seconds=60),
        min_requests: int = 4,
        min_distinct_paths: int = 3,
        min_not_found: int = 2,
    ) -> None:
        self.window = window
        self.min_requests = min_requests
        self.min_distinct_paths = min_distinct_paths
        self.min_not_found = min_not_found

    def detect(self, events: list[LogEvent]) -> list[SecurityAlert]:
        by_ip: dict[str, list[tuple[LogEvent, str]]] = defaultdict(list)
        for event in events:
            if not event.request_target:
                continue
            try:
                path = urlsplit(_decoded_target(event)).path.lower()
            except ValueError:
                # Malformed attacker-controlled URI must not abort the entire scan.
                continue
            if any(pattern.search(path) for pattern in ENUMERATION_PATHS):
                by_ip[event.source_ip].append((event, path))

        alerts = []
        for source_ip, probes in by_ip.items():
            probes.sort(key=lambda item: item[0].timestamp)
            start = 0
            while start < len(probes):
                first_event = probes[start][0]
                end = start
                while end < len(probes) and probes[end][0].timestamp - first_event.timestamp <= self.window:
                    end += 1
                window_probes = probes[start:end]
                paths = sorted({path for _, path in window_probes})
                not_found_count = sum(event.status_code == 404 for event, _ in window_probes)
                if (
                    len(window_probes) >= self.min_requests
                    and len(paths) >= self.min_distinct_paths
                    and not_found_count >= self.min_not_found
                ):
                    alerts.append(
                        SecurityAlert(
                            id=f"NGX-ENUM-{len(alerts) + 1:04d}",
                            timestamp=window_probes[-1][0].timestamp,
                            alert_type="web_enumeration",
                            title="偵測到 Web 路徑列舉",
                            severity=Severity.MEDIUM,
                            source_ip=source_ip,
                            evidence=[
                                f"{len(window_probes)} 次敏感路徑請求，涵蓋 {len(paths)} 個不同路徑（{int(self.window.total_seconds())} 秒內）",
                                f"其中 {not_found_count} 次回應為 HTTP 404",
                                "探測路徑：" + ", ".join(paths[:8]),
                            ],
                            related_events=[event for event, _ in window_probes],
                            summary="同一來源在短時間內依序探測多個常見管理介面或敏感檔案路徑，行為符合自動化 Web enumeration。",
                            recommendation="確認設定檔、版本控制資料及備份檔未暴露於 Web root，並檢查這些路徑是否有非 404 的回應。",
                        )
                    )
                    start = end
                else:
                    start += 1
        return alerts


def detect_nginx_alerts(events: list[LogEvent]) -> list[SecurityAlert]:
    alerts = SQLiDetector().detect(events)
    alerts.extend(XSSDetector().detect(events))
    alerts.extend(EnumerationDetector().detect(events))
    return sorted(alerts, key=lambda alert: alert.timestamp, reverse=True)
