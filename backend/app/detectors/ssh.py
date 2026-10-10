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
                evidence = f"{len(burst)} failed authentications within {int(window.total_seconds())} seconds"
                new_burst = last_qualifying_failure is None or (
                    end_event.timestamp - last_qualifying_failure > window
                )
                if new_burst:
                    active_brute_force_alert = SecurityAlert(
                        id=f"SSH-{sequence:04d}",
                        timestamp=end_event.timestamp,
                        alert_type="ssh_brute_force",
                        title="SSH Brute-force attempt",
                        severity=Severity.HIGH,
                        source_ip=source_ip,
                        username=burst[-1].username,
                        evidence=[evidence],
                        related_events=burst,
                        summary=f"Source {source_ip} made repeated SSH authentication attempts in a short period, consistent with automated password guessing. This indicates an attempt, not confirmed access.",
                        recommendation="Review SSH authentication logs and source activity to verify legitimate administration or testing.",
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
                    title="Successful SSH authentication after repeated failures",
                    severity=Severity.HIGH,
                    source_ip=source_ip,
                    username=success.username,
                    evidence=[f"{len(prior_failures)} failed authentications in the 10 minutes before successful authentication", "Successful authentication shares the source and account of the failed attempts"],
                    related_events=related,
                    summary=f"Source {source_ip} successfully authenticated as {success.username} after repeated failures. This may indicate credential guessing, but does not by itself confirm account compromise.",
                    recommendation="Confirm this login with the account owner and review subsequent commands and privilege escalation in the SSH session.",
                )
            )
            sequence += 1

    return sorted(alerts, key=lambda alert: alert.timestamp, reverse=True)
