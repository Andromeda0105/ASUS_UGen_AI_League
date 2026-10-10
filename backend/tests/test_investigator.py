import json
import unittest
from unittest.mock import patch
from fastapi import HTTPException
from app.copilot import OllamaError
from app.intelligence_models import InvestigationRequest
from app.investigator import run_hypothesis_investigation
from app.main import SCANS, get_graph, get_hypotheses, investigate_incident, scan_sample
from app.models import ScanRequest


class InvestigatorTests(unittest.TestCase):
    def setUp(self):
        self.scan = scan_sample(ScanRequest(with_ai=False))
        self.store = SCANS[self.scan.scan_id]
        self.report = self.scan.hypotheses[0]
        self.incident_id = self.report.incident_id

    def final_message(self):
        return {"content": json.dumps({
            "summary": "Current logs describe attempts and successful authentication but cannot identify the operator.",
            "assessment": [{"text": "Competing explanations still need verification.", "evidence_ids": [self.incident_id]}],
            "recommendations": [{"text": "Compare source activity with account owner records.", "evidence_ids": [self.incident_id]}],
            "missing_evidence": ["Process telemetry and attribution are missing."], "confidence": 0.6,
            "hypothesis_evaluations": [{"hypothesis_id": h.id, "status": "plausible", "confidence": h.confidence,
                 "inference": "This explanation may fit some records, but operator attribution is missing.", "evidence_ids": [self.incident_id],
                 "graph_edge_ids": []} for h in self.report.hypotheses],
        }, ensure_ascii=False)}

    def test_offline_readonly_investigation_checks_questions_then_stops(self):
        result = run_hypothesis_investigation(self.store, self.incident_id)
        self.assertEqual(result.ai_status, "skipped")
        self.assertEqual(result.report.tool_calls, 3)
        self.assertEqual(result.report.iteration_count, 1)
        self.assertEqual(result.report.stop_reason, "unavailable_telemetry")
        self.assertEqual(sum(q.status == "answered" for q in result.report.questions), 3)
        after = next(q for q in result.report.questions if q.evidence_type == "post_login_ssh_http")
        self.assertIn("0 matching records", after.answer)
        self.assertIn("neither establish", after.answer)
        self.assertNotIn("raw_log", json.dumps(result.investigation))

    def test_budgets_zero_and_one_are_hard_limits(self):
        for budget in (0, 1):
            result = run_hypothesis_investigation(self.store, self.incident_id, tool_budget=budget)
            self.assertLessEqual(result.report.tool_calls, budget)
            self.assertEqual(result.report.stop_reason, "tool_budget_exhausted")

    def test_next_request_only_checks_remaining_questions(self):
        first = run_hypothesis_investigation(self.store, self.incident_id, tool_budget=1)
        second = run_hypothesis_investigation(self.store, self.incident_id, tool_budget=4)
        self.assertEqual((first.report.tool_calls, second.report.tool_calls), (1, 2))
        self.assertEqual(second.report.stop_reason, "unavailable_telemetry")

    def test_single_selected_question_and_unknown_question(self):
        q = next(q for q in self.report.questions if q.answerable)
        result = run_hypothesis_investigation(self.store, self.incident_id, question_ids=[q.id], tool_budget=1)
        self.assertEqual(result.report.tool_calls, 1)
        with self.assertRaises(ValueError):
            run_hypothesis_investigation(self.store, self.incident_id, question_ids=["invented"])
        unanswerable = next(q for q in self.report.questions if not q.answerable)
        with self.assertRaises(ValueError):
            run_hypothesis_investigation(self.store, self.incident_id, question_ids=[unanswerable.id])

    def test_model_plan_cannot_invent_tools_or_questions(self):
        invalid = {"content": '{"question_ids":["block_ip"]}'}
        with patch("app.investigator.chat", side_effect=[invalid, self.final_message()]) as chat:
            result = run_hypothesis_investigation(self.store, self.incident_id, with_ai=True)
        self.assertEqual(result.ai_status, "completed")
        self.assertEqual(result.report.tool_calls, 3)
        self.assertTrue(all(t["tool"] != "block_ip" for t in result.investigation))
        self.assertTrue(result.ai_warnings)
        self.assertEqual(chat.call_count, 2)
        self.assertNotIn("raw_log", json.dumps(chat.call_args.args[0]))

    def test_model_can_prioritize_known_questions(self):
        chosen = [q.id for q in self.report.questions if q.answerable][::-1]
        with patch("app.investigator.chat", side_effect=[{"content": json.dumps({"question_ids": chosen})}, self.final_message()]):
            result = run_hypothesis_investigation(self.store, self.incident_id, with_ai=True)
        self.assertEqual(result.investigation[0]["question_id"], chosen[0])
        self.assertEqual(result.investigation[0]["origin"], "model")
        self.assertEqual({h.confidence_origin for h in result.report.hypotheses}, {"ai_bounded"})

    def test_ai_failure_still_finishes_safe_queries(self):
        with patch("app.investigator.chat", side_effect=OllamaError("offline")) as chat:
            result = run_hypothesis_investigation(self.store, self.incident_id, with_ai=True)
        self.assertEqual(result.ai_status, "unavailable")
        self.assertEqual(result.report.tool_calls, 3)
        self.assertEqual(chat.call_count, 1)
        self.assertTrue(result.report.hypotheses)

    def test_unknown_hypothesis_evidence_and_graph_references_are_rejected(self):
        for field, value in [("hypothesis_id", "invented"), ("evidence_ids", ["invented"]), ("graph_edge_ids", ["invented"])]:
            payload = json.loads(self.final_message()["content"])
            payload["hypothesis_evaluations"][0][field] = value
            with patch("app.investigator.chat", return_value={"content": json.dumps(payload)}):
                result = run_hypothesis_investigation(self.store, self.incident_id, with_ai=True, tool_budget=0)
            self.assertEqual(result.ai_status, "unavailable")
            self.assertIsNone(result.ai_analysis)

    def test_unsupported_certainty_and_confidence_are_not_promoted(self):
        payload = json.loads(self.final_message()["content"])
        for h in payload["hypothesis_evaluations"]:
            h["status"], h["confidence"] = "supported", 0.99
        with patch("app.investigator.chat", return_value={"content": json.dumps(payload)}):
            result = run_hypothesis_investigation(self.store, self.incident_id, with_ai=True, tool_budget=0)
        self.assertEqual(result.ai_status, "completed")
        self.assertNotIn("supported", [h.status for h in result.report.hypotheses])
        self.assertTrue(all(h.confidence <= 0.65 for h in result.report.hypotheses))
        self.assertTrue(result.ai_warnings)

    def test_ai_cannot_present_confirmed_compromise_as_fact(self):
        payload = json.loads(self.final_message()["content"])
        payload["summary"] = "Confirmed compromise: the attacker successfully logged in."
        with patch("app.investigator.chat", return_value={"content": json.dumps(payload)}):
            result = run_hypothesis_investigation(self.store, self.incident_id, with_ai=True, tool_budget=0)
        self.assertEqual(result.ai_status, "unavailable")
        self.assertEqual(result.report.hypotheses[0].confidence_origin, "rule")

    def test_graph_and_hypothesis_endpoints_and_wrong_scan(self):
        self.assertEqual(get_graph(self.scan.scan_id), self.store.graph)
        self.assertEqual(get_hypotheses(self.scan.scan_id)[0].incident_id, self.incident_id)
        result = investigate_incident(self.scan.scan_id, self.incident_id, InvestigationRequest(tool_budget=1))
        self.assertEqual(result.report.tool_calls, 1)
        with self.assertRaises(HTTPException):
            investigate_incident(self.scan.scan_id, "unknown", InvestigationRequest())

    def test_investigation_cannot_change_graph_or_alerts(self):
        original_graph = self.store.graph.model_dump_json()
        original_alerts = [a.model_dump_json() for a in self.store.alerts]
        run_hypothesis_investigation(self.store, self.incident_id)
        self.assertEqual(original_graph, self.store.graph.model_dump_json())
        self.assertEqual(original_alerts, [a.model_dump_json() for a in self.store.alerts])

    def test_new_readonly_evidence_is_neutral_and_observed_not_confirmed(self):
        from datetime import timedelta
        from app.models import LogEvent
        from app.evidence import EvidenceStore
        added = LogEvent(timestamp=self.store.incidents[0].end_time + timedelta(seconds=1), source="nginx.access.log",
                         event_type="http_request", source_ip="10.0.0.8", request_target="/normal", status_code=200,
                         raw_log="additional normal request")
        store = EvidenceStore([*self.store.events, added], list(self.store.alerts), list(self.store.incidents))
        result = run_hypothesis_investigation(store, self.incident_id, tool_budget=1)
        self.assertTrue(all(added.id in h.neutral_evidence_ids for h in result.report.hypotheses))
        self.assertTrue(any(added.id in fact.evidence_ids for fact in result.report.observed_facts))
        self.assertNotIn("supported", [h.status for h in result.report.hypotheses])

    def test_truncated_results_remain_explicit(self):
        original = self.store.execute
        def truncated(name, args):
            result = original(name, args)
            result["truncated"] = True
            return result
        with patch.object(self.store, "execute", side_effect=truncated):
            result = run_hypothesis_investigation(self.store, self.incident_id, tool_budget=1)
        self.assertTrue(result.report.questions[0].truncated)
        self.assertTrue(any("Truncated" in item for item in result.report.missing_evidence))
