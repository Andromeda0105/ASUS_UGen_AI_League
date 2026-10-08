import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from fastapi import HTTPException

from app.copilot import OllamaError, analyze_security_scan, validate_analysis, enforce_readonly_recommendations
from app.detectors.nginx import detect_nginx_alerts
from app.detectors.ssh import detect_ssh_alerts
from app.evidence import EvidenceStore
from app.incidents import correlate_incidents
from app.main import SCANS, get_evidence, investigate, scan_sample
from app.models import LogEvent, ScanRequest
from app.parsers.nginx import parse_nginx_line
from app.parsers.ssh import parse_ssh_line


BASE = datetime(2026, 9, 30, 15, 0, tzinfo=timezone(timedelta(hours=8)))


def auth(offset, user="alice", success=False, ip="10.0.0.8"):
    return LogEvent(timestamp=BASE + timedelta(seconds=offset), source_ip=ip, username=user,
                    event_type="authentication_success" if success else "authentication_failed",
                    raw_log=f"{offset}:{user}:{success}:{ip}")


def request(target):
    return parse_nginx_line(f'10.0.0.8 - - [30/Sep/2026:15:01:01 +0800] "GET {target} HTTP/1.1" 404 150 "-" "demo"')


def scenario():
    return scan_sample(ScanRequest(sample="scenario:multi_stage", with_ai=False))


def report(ref):
    return dict(summary="需調查可疑活動，尚不能確認入侵。", assessment=[dict(text="有規則告警", evidence_ids=[ref])],
                recommendations=[dict(text="比對帳號擁有者活動", evidence_ids=[ref])],
                missing_evidence=["缺少登入後程序活動"], confidence=0.6)


class CorrectnessTests(unittest.TestCase):
    def test_alice_fail_bob_success_is_not_suspicious(self):
        alerts = detect_ssh_alerts([auth(i) for i in range(5)] + [auth(10, "bob", True)])
        self.assertEqual([a.alert_type for a in alerts], ["ssh_brute_force"])

    def test_same_account_success_is_suspicious_even_with_unsorted_input(self):
        events = [auth(i) for i in range(5)] + [auth(10, success=True)]
        self.assertEqual({a.alert_type for a in detect_ssh_alerts(events[::-1])},
                         {"ssh_brute_force", "suspicious_login"})

    def test_other_source_success_is_not_suspicious(self):
        alerts = detect_ssh_alerts([auth(i) for i in range(5)] + [auth(10, success=True, ip="10.0.0.9")])
        self.assertNotIn("suspicious_login", [a.alert_type for a in alerts])

    def test_slow_failures_do_not_trigger_bruteforce(self):
        self.assertEqual(detect_ssh_alerts([auth(i * 120) for i in range(5)]), [])

    def test_same_timestamp_failures_are_not_prior_failures(self):
        alerts = detect_ssh_alerts([auth(0) for _ in range(5)] + [auth(0, success=True)])
        self.assertNotIn("suspicious_login", [a.alert_type for a in alerts])

    def test_benign_keywords_and_comment_text_do_not_alert(self):
        for target in ["/search?q=select+database+union", "/docs/javascript-script-HTML", "/article/two--words",
                       "/search?q=%3Cimg%20src=x%3E", "/search?q=OR+1=2", "/.env", "//[malformed"]:
            with self.subTest(target=target):
                self.assertEqual(detect_nginx_alerts([request(target)]), [])

    def test_invalid_syslog_date_is_skipped(self):
        self.assertIsNone(parse_ssh_line("Sep 99 15:00:00 host sshd[1]: Failed password for admin from 10.0.0.8 port 1234", year=2026))

    def test_plus_encoded_tautology_is_detected(self):
        self.assertEqual(detect_nginx_alerts([request("/search?q=1%27+OR+%271%27=%271")])[0].alert_type, "sqli_attempt")


class IncidentTests(unittest.TestCase):
    def test_multisource_scenario_has_ordered_critical_incident(self):
        result = scenario()
        self.assertEqual((result.event_count, len(result.alerts), len(result.incidents)), (10, 3, 1))
        incident = result.incidents[0]
        self.assertEqual(incident.severity, "Critical")
        self.assertEqual(incident.attack_stages, ["web_reconnaissance", "credential_attack", "suspicious_authentication"])
        self.assertEqual(len({a.id for a in result.alerts}), 3)
        self.assertTrue(all(t.event_ids for t in incident.timeline))

    def test_multiple_samples_deduplicate_evidence(self):
        result = scan_sample(ScanRequest(samples=["ssh:bruteforce.log", "ssh:bruteforce.log", "nginx:mix.log"], with_ai=False))
        self.assertEqual(result.event_count, 22)
        self.assertEqual(len(result.alerts), 4)
        self.assertEqual(len({a.id for a in result.alerts}), 4)

    def test_ids_are_stable_across_scans(self):
        first, second = scenario(), scenario()
        self.assertEqual(first.incidents[0].id, second.incidents[0].id)
        self.assertEqual([a.id for a in first.alerts], [a.id for a in second.alerts])
        self.assertNotEqual(first.scan_id, second.scan_id)

    def test_time_window_does_not_chain_indefinitely(self):
        alerts = scenario().alerts
        # Space chronological alerts by nine minutes; third must form a new group.
        for n, alert in enumerate(sorted(alerts, key=lambda a: a.timestamp)):
            alert.timestamp = BASE + timedelta(minutes=n * 9)
            alert.related_events = []
        self.assertEqual(len(correlate_incidents(alerts)), 2)

    def test_distinct_ips_are_not_merged(self):
        alerts = scenario().alerts
        alerts[0].source_ip = "10.0.0.9"
        self.assertEqual(len(correlate_incidents(alerts)), 2)
        self.assertNotIn("Critical", [i.severity for i in correlate_incidents(alerts)])

    def test_reversed_stages_do_not_escalate(self):
        alerts = scenario().alerts
        recon = next(a for a in alerts if a.alert_type == "web_enumeration")
        recon.timestamp = BASE + timedelta(minutes=7)
        self.assertNotIn("Critical", [i.severity for i in correlate_incidents(alerts)])

    def test_wrong_account_does_not_escalate(self):
        alerts = scenario().alerts
        brute = next(a for a in alerts if a.alert_type == "ssh_brute_force")
        for event in brute.related_events:
            event.username = "alice"
        self.assertNotIn("Critical", [i.severity for i in correlate_incidents(alerts)])

    def test_timezone_offsets_compare_same_instant(self):
        result = scenario()
        for alert in result.alerts:
            alert.timestamp = alert.timestamp.astimezone(timezone.utc)
        self.assertEqual(correlate_incidents(result.alerts)[0].severity, "Critical")


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.result = scenario()
        self.store = SCANS[self.result.scan_id]

    def test_event_queries_are_readonly_filtered_and_bounded(self):
        output = self.store.execute("search_events", {"source_ip": "10.0.0.8", "limit": 2})
        self.assertEqual(output["total"], 10)
        self.assertTrue(output["truncated"])
        self.assertNotIn("raw_log", json.dumps(output))
        self.assertEqual(self.store.execute("search_events", {"source_ip": "10.0.0.99"})["items"], [])
        self.assertEqual(self.store.execute("get_user_logins", {"username": "admin"})["total"], 1)

    def test_tool_allowlist_and_validation(self):
        for tool, args in [("block_ip", {}), ("get_user_logins", {}), ("search_events", {"limit": 1000}),
                           ("search_events", {"path": "/etc/passwd"}),
                           ("search_events", {"start": "2026-09-30T15:00:00"}),
                           ("get_incident_timeline", {"incident_id": "not-this-scan"})]:
            with self.subTest(tool=tool, args=args), self.assertRaises(ValueError):
                self.store.execute(tool, args)

    def test_evidence_routes_and_unknown_scan(self):
        item = get_evidence(self.result.scan_id, self.result.alerts[0].id)
        self.assertTrue(item.related_events[0].raw_log)
        timeline = investigate(self.result.scan_id, "get_incident_timeline", incident_id=self.result.incidents[0].id)
        self.assertEqual(timeline["total"], 3)
        with self.assertRaises(HTTPException):
            get_evidence("missing", item.id)

    def test_structured_ai_references_are_validated(self):
        valid = report(self.result.alerts[0].id)
        self.assertEqual(validate_analysis(json.dumps(valid), self.store).confidence, 0.6)
        for invalid in [report("invented"), {**valid, "confidence": 5}, {**valid, "thinking": "prompt echo"}]:
            with self.assertRaises(OllamaError):
                validate_analysis(json.dumps(invalid), self.store)
        with self.assertRaises(OllamaError):
            validate_analysis("</think>### 事件摘要", self.store)

    def test_ai_calls_readonly_tool_then_requests_structured_output(self):
        tool = {"role": "assistant", "tool_calls": [{"function": {
            "name": "get_user_logins", "arguments": {"username": "admin"}}}]}
        final = {"content": json.dumps(report(self.result.alerts[0].id))}
        with patch("app.copilot.chat", side_effect=[tool, final]) as chat:
            analysis, trace = analyze_security_scan("scenario:multi_stage", self.store)
            self.assertEqual(trace[0]["result"]["total"], 1)
            self.assertEqual(analysis.confidence, 0.6)
            self.assertIn("format", chat.call_args.kwargs)
            self.assertNotIn("raw_log", json.dumps(chat.call_args.args[0]))

    def test_change_recommendations_are_filtered_and_reported(self):
        data = report(self.result.alerts[0].id)
        data["recommendations"] = [
            {"text": "確認 admin 帳號 SSH 會話後續執行的命令", "evidence_ids": [self.result.alerts[0].id]},
            {"text": "檢查 Web 路徑，並修復 404 路徑", "evidence_ids": [self.result.alerts[0].id]},
            {"text": "啟用 SSH 密碼強度規則", "evidence_ids": [self.result.alerts[0].id]},
        ]
        analysis = validate_analysis(json.dumps(data), self.store)
        notes = enforce_readonly_recommendations(analysis, self.store)
        self.assertEqual(len(analysis.recommendations), 1)
        self.assertIn("2 項", notes[0])

    def test_all_unsafe_recommendations_use_evidence_based_readonly_fallback(self):
        data = report(self.result.alerts[0].id)
        data["recommendations"][0]["text"] = "sudo ufw block 10.0.0.8"
        analysis = validate_analysis(json.dumps(data), self.store)
        self.assertTrue(enforce_readonly_recommendations(analysis, self.store))
        self.assertTrue(analysis.recommendations[0].text.startswith("比對"))
        self.assertEqual(analysis.recommendations[0].evidence_ids, [self.store.incidents[0].id])

    def test_backend_seeds_evidence_when_model_skips_tools(self):
        with patch("app.copilot.chat", side_effect=[{"content": "no tools"}, {"content": json.dumps(report(self.result.alerts[0].id))}]):
            _, trace = analyze_security_scan("test", self.store)
        self.assertEqual([t["tool"] for t in trace], ["get_incident_timeline", "search_events"])
        self.assertTrue(all(t["origin"] == "fallback" for t in trace))
        self.assertEqual(trace[1]["result"]["total"], 10)

    def test_unapproved_ai_tool_is_never_executed(self):
        tool = {"tool_calls": [{"function": {"name": "block_ip", "arguments": {}}}]}
        with patch("app.copilot.chat", side_effect=[tool, {"content": json.dumps(report(self.result.alerts[0].id))}]):
            _, trace = analyze_security_scan("test", self.store)
            self.assertIn("error", trace[0]["result"])

    def test_failed_ai_report_preserves_completed_tool_trace(self):
        tool = {"tool_calls": [{"function": {"name": "get_user_logins", "arguments": {"username": "admin"}}}]}
        with patch("app.investigator.chat", side_effect=[{"content": "{\"question_ids\": []}"}, {"content": "not JSON"}]):
            result = scan_sample(ScanRequest(sample="scenario:multi_stage"))
        self.assertEqual(result.ai_status, "unavailable")
        self.assertEqual(next(t for t in result.investigation if t["tool"] == "get_user_logins")["result"]["total"], 1)
        self.assertEqual(len(result.alerts), 3)

    def test_ai_offline_keeps_alerts_and_incidents(self):
        with patch("app.main.analyze_security_scan", side_effect=OllamaError("offline")):
            result = scan_sample(ScanRequest(sample="scenario:multi_stage"))
        self.assertEqual(result.ai_status, "unavailable")
        self.assertEqual(len(result.alerts), 3)
        self.assertEqual(len(result.incidents), 1)


if __name__ == "__main__":
    unittest.main()
