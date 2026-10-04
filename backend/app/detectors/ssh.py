from collections import defaultdict
from datetime import timedelta

from app.models import LogEvent, SecurityAlert, Severity


def detect_ssh_alerts(
    events: list[LogEvent], *, threshold: int = 5, window: timedelta = timedelta(seconds=60)
) -> list[SecurityAlert]:
    """Generate explainable brute-force and possible-compromise alerts."""
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.source_ip].append(event)

    alerts: list[SecurityAlert] = []
    sequence = 1
    for source_ip, source_events in sorted(by_ip.items()):
        source_events.sort(key=lambda event: event.timestamp)
        failures = [event for event in source_events if event.event_type == "authentication_failed"]
        successes = [event for event in source_events if event.event_type == "authentication_success"]

        # Sliding windows avoid treating a long-running, low-rate source as a burst.
        active_brute_force_alert = None
        last_qualifying_failure = None
        for end_index, end_event in enumerate(failures):
            start_index = end_index
            while start_index > 0 and end_event.timestamp - failures[start_index - 1].timestamp <= window:
                start_index -= 1
            burst = failures[start_index : end_index + 1]
            if len(burst) >= threshold:
                evidence = f"{len(burst)} 次失敗驗證發生於 {int(window.total_seconds())} 秒內"
                new_burst = last_qualifying_failure is None or (
                    end_event.timestamp - last_qualifying_failure > window
                )
                if new_burst:
                    active_brute_force_alert = SecurityAlert(
                        id=f"SSH-{sequence:04d}",
                        timestamp=end_event.timestamp,
                        alert_type="ssh_brute_force",
                        title="SSH 暴力破解嘗試",
                        severity=Severity.HIGH,
                        source_ip=source_ip,
                        username=burst[-1].username,
                        evidence=[evidence],
                        related_events=burst,
                        summary=f"來源 {source_ip} 在短時間內嘗試多次 SSH 驗證，行為符合自動化密碼猜測特徵。這代表攻擊嘗試，不代表已取得存取權。",
                        recommendation="查閱 SSH 驗證日誌與來源活動，確認是否為合法管理或測試流量。",
                    )
                    alerts.append(active_brute_force_alert)
                    sequence += 1
                else:
                    # Keep the strongest/latest sliding window as the alert evidence.
                    active_brute_force_alert.timestamp = end_event.timestamp
                    active_brute_force_alert.username = end_event.username
                    active_brute_force_alert.evidence = [evidence]
                    active_brute_force_alert.related_events = burst
                last_qualifying_failure = end_event.timestamp

        for success in successes:
            prior_failures = [
                event for event in failures
                if success.username is not None and event.username == success.username
                and timedelta(0) < success.timestamp - event.timestamp <= timedelta(minutes=10)
            ]
            if len(prior_failures) < threshold:
                continue
            related = prior_failures + [success]
            alerts.append(
                SecurityAlert(
                    id=f"SSH-{sequence:04d}",
                    timestamp=success.timestamp,
                    alert_type="suspicious_login",
                    title="多次失敗後 SSH 登入成功",
                    severity=Severity.HIGH,
                    source_ip=source_ip,
                    username=success.username,
                    evidence=[f"成功登入前 10 分鐘內有 {len(prior_failures)} 次失敗驗證", "成功登入來源與帳號均與失敗嘗試相同"],
                    related_events=related,
                    summary=f"來源 {source_ip} 在多次驗證失敗後成功登入帳號 {success.username}。這是可能帳號遭猜測的訊號，尚不能單憑此事件確認帳號已遭入侵。",
                    recommendation="向帳號擁有者確認這次登入，並檢視該 SSH session 後續執行的命令及權限提升活動。",
                )
            )
            sequence += 1

    return sorted(alerts, key=lambda alert: alert.timestamp, reverse=True)
