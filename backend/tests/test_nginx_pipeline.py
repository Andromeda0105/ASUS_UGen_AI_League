import unittest

from app.detectors.nginx import detect_nginx_alerts
from app.copilot import extract_final_report
from app.main import scan_sample
from app.models import ScanRequest
from app.parsers.nginx import parse_nginx_line, parse_nginx_logs


class NginxParserTests(unittest.TestCase):
    def test_parses_combined_access_log_and_decodes_structure(self):
        line = (
            '10.0.0.9 - - [30/Sep/2026:16:20:10 +0800] '
            '"GET /products?id=1%27%20OR%20%271%27=%271 HTTP/1.1" '
            '200 1536 "-" "Mozilla/5.0"'
        )
        event = parse_nginx_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.source, "nginx.access.log")
        self.assertEqual(event.source_ip, "10.0.0.9")
        self.assertEqual(event.request_method, "GET")
        self.assertEqual(event.status_code, 200)
        self.assertIn("%27", event.request_target)
        self.assertIsNone(parse_nginx_line("not an access log line"))


class NginxDetectionTests(unittest.TestCase):
    def load(self, name):
        from pathlib import Path

        root = Path(__file__).resolve().parents[2]
        return parse_nginx_logs((root / "samples" / name).read_text(encoding="utf-8"))

    def test_normal_traffic_does_not_alert(self):
        self.assertEqual(detect_nginx_alerts(self.load("normal.log")), [])

    def test_sqli_and_xss_are_detected_as_attempts(self):
        sqli = detect_nginx_alerts(self.load("sqli.log"))
        xss = detect_nginx_alerts(self.load("xss.log"))
        self.assertEqual([alert.alert_type for alert in sqli], ["sqli_attempt", "sqli_attempt"])
        self.assertEqual([alert.alert_type for alert in xss], ["xss_attempt", "xss_attempt"])
        self.assertTrue(all("攻擊嘗試" in alert.summary for alert in sqli + xss))

    def test_enumeration_correlates_multiple_paths_from_one_ip(self):
        alerts = detect_nginx_alerts(self.load("enumeration.log"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "web_enumeration")
        self.assertEqual(alerts[0].source_ip, "10.0.0.8")
        self.assertEqual(len(alerts[0].related_events), 6)

    def test_mixed_sample_combines_all_three_detector_types(self):
        alerts = detect_nginx_alerts(self.load("mix.log"))
        self.assertEqual(
            {alert.alert_type for alert in alerts},
            {"web_enumeration", "sqli_attempt", "xss_attempt"},
        )

    def test_sample_scan_uses_shared_scan_result_without_ai(self):
        result = scan_sample(ScanRequest(sample="nginx:mix.log", with_ai=False))
        self.assertEqual(result.ai_status, "skipped")
        self.assertEqual(result.sample, "nginx:mix.log")
        self.assertGreater(result.event_count, 0)
        self.assertEqual(len(result.alerts), 3)

    def test_copilot_report_strips_qwen_reasoning_preamble(self):
        response = (
            "首先，我需要遵守系統提示並整理事件。\n"
            "</think>\n\n"
            "### 事件摘要\n來源包含可疑 SQL 請求。\n\n"
            "### 判讀依據\n- 規則命中 SQL 特徵。\n"
        )
        report = extract_final_report(response)
        self.assertTrue(report.startswith("### 事件摘要"))
        self.assertNotIn("首先", report)


class SharedPipelineRegressionTests(unittest.TestCase):
    def test_existing_ssh_samples_keep_their_expected_alert_counts(self):
        expected = {
            "ssh:normal.log": 0,
            "ssh:bruteforce.log": 1,
            "ssh:suspicious_login.log": 2,
            "ssh:compromised_login.log": 3,
        }
        for sample, alert_count in expected.items():
            with self.subTest(sample=sample):
                result = scan_sample(ScanRequest(sample=sample, with_ai=False))
                self.assertEqual(len(result.alerts), alert_count)


if __name__ == "__main__":
    unittest.main()
