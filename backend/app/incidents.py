"""Deterministic correlation. Same-IP proximity is a hypothesis, not identity proof."""
from collections import defaultdict
from datetime import timedelta
from hashlib import sha256

from app.models import Incident, SecurityAlert, Severity, TimelineEntry

STAGES = {
    "web_enumeration": "web_reconnaissance",
    "ssh_brute_force": "credential_attack",
    "suspicious_login": "suspicious_authentication",
    "sqli_attempt": "web_exploitation_attempt",
    "xss_attempt": "web_exploitation_attempt",
}


def correlate_incidents(alerts: list[SecurityAlert], window=timedelta(minutes=10)) -> list[Incident]:
    by_ip = defaultdict(list)
    for alert in alerts:
        by_ip[alert.source_ip].append(alert)
    incidents = []
    for ip, items in sorted(by_ip.items()):
        groups = []
        for alert in sorted(items, key=lambda a: (a.timestamp, a.id)):
            start = min((e.timestamp for e in alert.related_events), default=alert.timestamp)
            if not groups or alert.timestamp - min(start, groups[-1][0]) > window:
                groups.append((start, [alert]))
            else:
                groups[-1][1].append(alert)
                groups[-1] = (min(start, groups[-1][0]), groups[-1][1])
        for start, group in groups:
            timeline = [TimelineEntry(timestamp=a.timestamp, stage=STAGES.get(a.alert_type, a.alert_type),
                                      alert_id=a.id, event_ids=[e.id for e in a.related_events]) for a in group]
            # Elevation requires ordered reconnaissance -> failures for the successful account -> login.
            multistage = any(
                recon.timestamp < min((e.timestamp for e in brute.related_events), default=brute.timestamp)
                and brute.timestamp < login.timestamp
                and len([e for e in brute.related_events if e.username == login.username]) >= 5
                for recon in group if recon.alert_type == "web_enumeration"
                for brute in group if brute.alert_type == "ssh_brute_force"
                for login in group if login.alert_type == "suspicious_login"
            )
            severity = Severity.CRITICAL if multistage else (
                Severity.HIGH if any(a.severity == Severity.HIGH for a in group) else Severity.MEDIUM)
            ids = [a.id for a in group]
            incidents.append(Incident(
                id="INC-" + sha256("|".join(ids).encode()).hexdigest()[:12],
                title="可能的多階段伺服器入侵活動" if multistage else "相關安全告警調查",
                severity=severity, source_ips=[ip],
                usernames=sorted({a.username for a in group if a.username}), alert_ids=ids,
                start_time=start, end_time=group[-1].timestamp,
                attack_stages=list(dict.fromkeys(t.stage for t in timeline)), timeline=timeline,
                correlation_reason=("同一來源 10 分鐘內依序出現 Web 探測、同帳號 SSH 密碼猜測與可疑成功登入。"
                                    if multistage else "以同一來源 IP 與首筆證據起算 10 分鐘範圍建立調查群組。")
                + "IP 可能共用；時間關聯不證明同一攻擊者或已入侵，需確認主機與帳號活動。",
            ))
    return sorted(incidents, key=lambda i: i.end_time, reverse=True)
