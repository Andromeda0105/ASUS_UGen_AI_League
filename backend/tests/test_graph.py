import json
import unittest
from app.graph import build_evidence_graph
from app.main import SCANS, scan_sample
from app.models import ScanRequest


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.result = scan_sample(ScanRequest(sample="scenario:multi_stage", with_ai=False))
        self.store = SCANS[self.result.scan_id]
        self.graph = build_evidence_graph(self.store)

    def test_all_initial_node_types_and_traceable_edges(self):
        self.assertEqual({n.node_type for n in self.graph.nodes}, {"event", "alert", "incident", "ip", "user", "endpoint"})
        ids = {n.id for n in self.graph.nodes}
        self.assertTrue(all(e.source in ids and e.target in ids and set(e.evidence_ids) <= self.store.ids for e in self.graph.edges))
        self.assertNotIn("raw_log", self.graph.model_dump_json())

    def test_observed_authentication_is_distinct_from_inferred_progression(self):
        login = [e for e in self.graph.edges if e.relation == "AUTHENTICATED_AS"]
        self.assertTrue(login and all(e.edge_type == "observed" for e in login))
        progression = [e for e in self.graph.edges if e.relation == "POSSIBLE_ATTACK_PROGRESSION"]
        self.assertEqual(len(progression), 2)
        self.assertTrue(all(e.edge_type == "inferred" and e.reasons and 0 <= e.confidence <= 1 for e in progression))

    def test_graph_is_deterministic_and_has_unique_ids(self):
        self.assertEqual(self.graph, build_evidence_graph(self.store))
        self.assertEqual(len({e.id for e in self.graph.edges}), len(self.graph.edges))
        self.assertEqual(len({n.id for n in self.graph.nodes}), len(self.graph.nodes))

    def test_normal_traffic_has_no_inferred_attack_edges(self):
        result = scan_sample(ScanRequest(sample="nginx:normal.log", with_ai=False))
        graph = build_evidence_graph(SCANS[result.scan_id])
        self.assertFalse(any(e.edge_type == "inferred" for e in graph.edges))
        self.assertTrue(graph.nodes)

    def test_all_parsed_samples_build_graphs(self):
        from app.main import get_samples
        for sample in get_samples():
            with self.subTest(sample=sample["name"]):
                result = scan_sample(ScanRequest(sample=sample["name"], with_ai=False))
                build_evidence_graph(SCANS[result.scan_id])
