import unittest
from app.evidence import EvidenceStore
from app.hypotheses import build_hypothesis_report
from app.main import SCANS, scan_sample
from app.models import ScanRequest


class HypothesisTests(unittest.TestCase):
    def setUp(self):
        result = scan_sample(ScanRequest(sample="scenario:multi_stage", with_ai=False))
        self.store = SCANS[result.scan_id]
        self.incident = self.store.incidents[0]
        self.report = build_hypothesis_report(self.store, self.incident)

    def test_multistage_generates_three_competing_templates(self):
        self.assertEqual({h.template for h in self.report.hypotheses},
                         {"possible_single_attacker_campaign", "possible_shared_source_activity", "possible_legitimate_successful_login"})
        self.assertTrue(all(h.missing_evidence and 0 <= h.confidence <= 1 for h in self.report.hypotheses))
        self.assertNotEqual(sum(h.confidence for h in self.report.hypotheses), 1)
        self.assertIn("不能區分", self.report.uncertainty)

    def test_evidence_and_edges_are_real_and_roles_disjoint(self):
        edges = {e.id for e in self.store.graph.edges}
        for h in self.report.hypotheses:
            supporting, contradicting, neutral = map(set, [h.supporting_evidence_ids, h.contradicting_evidence_ids, h.neutral_evidence_ids])
            self.assertTrue(supporting | contradicting | neutral <= self.store.ids)
            self.assertFalse(supporting & contradicting or supporting & neutral or contradicting & neutral)
            self.assertTrue(set(h.supporting_edge_ids + h.contradicting_edge_ids + h.neutral_edge_ids) <= edges)

    def test_shared_source_has_no_fabricated_nat_proof(self):
        shared = self.report.hypotheses[1]
        self.assertEqual(shared.supporting_evidence_ids, [])
        self.assertEqual(shared.status, "insufficient_evidence")
        self.assertTrue(shared.neutral_evidence_ids)

    def test_observed_facts_and_missing_telemetry_are_separate(self):
        self.assertEqual(len(self.report.observed_facts), 3)
        self.assertTrue(all(set(fact.evidence_ids) <= self.store.ids for fact in self.report.observed_facts))
        unavailable = [q for q in self.report.questions if not q.answerable]
        self.assertTrue(unavailable)
        self.assertTrue(all(q.suggested_tool is None and q.status == "unavailable" for q in unavailable))
        self.assertTrue(all(q.tool_arguments for q in self.report.questions if q.answerable))

    def test_reversed_timeline_contradicts_ordered_campaign_hypothesis(self):
        from datetime import timedelta
        recon = next(a for a in self.store.alerts if a.alert_type == "web_enumeration")
        recon.timestamp = self.incident.end_time + timedelta(seconds=20)
        updated = self.incident.model_copy(update={"end_time": recon.timestamp})
        store = EvidenceStore(list(self.store.events), list(self.store.alerts), [updated])
        report = build_hypothesis_report(store, updated)
        self.assertEqual(report.hypotheses[0].status, "contradicted")
        self.assertTrue(report.hypotheses[0].contradicting_evidence_ids)

    def test_single_alert_still_gets_two_hypotheses_and_normal_has_none(self):
        result = scan_sample(ScanRequest(sample="ssh:bruteforce.log", with_ai=False))
        self.assertEqual(len(SCANS[result.scan_id].hypothesis_reports[result.incidents[0].id].hypotheses), 2)
        normal = scan_sample(ScanRequest(sample="ssh:normal.log", with_ai=False))
        self.assertEqual(SCANS[normal.scan_id].hypothesis_reports, {})
