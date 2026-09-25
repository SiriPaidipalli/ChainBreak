import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from src.graph import AttackGraph
from src.incident import analyze_incident, load_events, missing_telemetry_events
from src.workflow import ContainmentWorkflow


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.graph = AttackGraph()
        self.graph.load_environment(Path(__file__).resolve().parents[1] / "data" / "environment.json")
        self.events = load_events()

    def test_events_load(self):
        self.assertEqual(len(self.events), 9)
        self.assertEqual(len({e.event_id for e in self.events}), 9)
        for event in self.events:
            self.assertTrue(event.timestamp and event.source and event.description and event.severity)
            self.assertIn(event.actor, self.graph.entities)
            self.assertIn(event.target, self.graph.entities)

    def test_correlation_includes_entities_and_exact_relationships(self):
        result = analyze_incident(self.graph, self.events)
        self.assertEqual(len(result.evidence), 9)
        self.assertEqual(set(result.supported_entities), set(self.graph.entities))
        self.assertEqual(result.supported_relationships[("dev-server", "deploy-token")], ("evt-004",))
        self.assertEqual(result.supported_relationships[("alice", "alice-laptop")], ("evt-001",))

    def test_both_paths_have_deterministic_coverage(self):
        result = analyze_incident(self.graph, self.events)
        self.assertEqual(len(result.paths), 2)
        for path in result.paths:
            self.assertEqual(path.supported_transitions, 5)
            self.assertEqual(path.total_transitions, 5)
            self.assertEqual(path.coverage, 1.0)
        self.assertEqual(result.evidence_coverage, 1.0)
        self.assertFalse(result.telemetry_incomplete)
        self.assertEqual(result, analyze_incident(self.graph, reversed(self.events)))

    def test_duplicate_events_do_not_inflate_coverage(self):
        self.assertEqual(analyze_incident(self.graph, self.events),
                         analyze_incident(self.graph, self.events * 2))

    def test_unknown_entities_and_wrong_behavior_do_not_support_edges(self):
        unknown = replace(self.events[0], actor="unknown", event_id="unknown")
        unrelated = replace(self.events[0], event_type="heartbeat", event_id="heartbeat")
        result = analyze_incident(self.graph, [unknown, unrelated])
        self.assertEqual(result.evidence, [unrelated])
        self.assertEqual(result.supported_relationships, {})
        self.assertEqual(result.attack_mappings, [])

    def test_reversed_edge_is_not_transition_evidence(self):
        event = replace(self.events[2], actor="dev-server", target="alice-laptop")
        result = analyze_incident(self.graph, [event])
        self.assertEqual(result.supported_relationships, {})
        self.assertEqual(result.attack_mappings, [])

    def test_risk_formula_and_bounds(self):
        full = analyze_incident(self.graph, self.events)
        self.assertEqual(full.risk_score, 100)
        self.assertEqual(full.severity, "critical")
        self.assertEqual(full.priority, "P1")
        for events in [self.events, missing_telemetry_events(self.events), []]:
            result = analyze_incident(self.graph, events)
            self.assertGreaterEqual(result.risk_score, 0)
            self.assertLessEqual(result.risk_score, 100)
            self.assertEqual(result.risk_score, sum(f.points for f in result.risk_factors))

    def test_asset_criticality_changes_risk_not_confidence(self):
        critical = analyze_incident(self.graph, self.events)
        self.graph.entities["customer-db"].criticality = "low"
        low = analyze_incident(self.graph, self.events)
        self.assertEqual(critical.risk_score - low.risk_score, 30)
        self.assertEqual(critical.confidence, low.confidence)

    def test_missing_telemetry_reduces_coverage_and_confidence(self):
        full = analyze_incident(self.graph, self.events)
        partial = analyze_incident(self.graph, missing_telemetry_events(self.events))
        self.assertEqual(len(partial.paths), 2)
        self.assertEqual([p.coverage for p in partial.paths], [0.6, 0.6])
        self.assertEqual(partial.evidence_coverage, 0.5)
        self.assertEqual(partial.confidence, 50.0)
        self.assertEqual(partial.confidence_level, "medium")
        self.assertLess(partial.confidence, full.confidence)
        self.assertEqual(partial.risk_score, 75)
        self.assertTrue(partial.telemetry_incomplete)

    def test_no_telemetry_still_reconstructs_paths(self):
        result = analyze_incident(self.graph, [])
        self.assertEqual(len(result.paths), 2)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.evidence_coverage, 0)
        self.assertTrue(result.telemetry_incomplete)
        self.assertEqual(result.evidence, [])
        self.assertEqual(result.attack_mappings, [])

    def test_missing_file_returns_empty_telemetry(self):
        with TemporaryDirectory() as directory:
            self.assertEqual(load_events(Path(directory) / "missing.json"), [])

    def test_mappings_require_specific_supporting_events(self):
        result = analyze_incident(self.graph, self.events)
        self.assertEqual({(m.technique_id, m.event_id) for m in result.attack_mappings}, {
            ("T1078", "evt-001"), ("T1059.001", "evt-002"),
            ("T1021.004", "evt-003"), ("T1552.001", "evt-004"), ("T1552.001", "evt-005"),
        })
        for event in self.events[:3]:
            removed = analyze_incident(self.graph, [e for e in self.events if e != event])
            self.assertNotIn(event.event_id, [m.event_id for m in removed.attack_mappings])
        partial = analyze_incident(self.graph, missing_telemetry_events(self.events))
        self.assertNotIn("T1552.001", [m.technique_id for m in partial.attack_mappings])

    def test_analysis_does_not_mutate_graph_or_events(self):
        original_graph, original_events = deepcopy(self.graph.__dict__), deepcopy(self.events)
        analyze_incident(self.graph, self.events)
        self.assertEqual(self.graph.__dict__, original_graph)
        self.assertEqual(self.events, original_events)

    def test_no_viable_paths_does_not_crash(self):
        self.graph.adjacency["alice"] = []
        result = analyze_incident(self.graph, self.events)
        self.assertEqual(result.paths, [])
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.risk_score, 0)

    def test_workflow_recommendation_and_approval_unchanged_with_any_coverage(self):
        for events in [self.events, missing_telemetry_events(self.events), []]:
            workflow = ContainmentWorkflow(self.graph, events=events)
            self.assertEqual(workflow.recommendation.operational_cost, 3)
            self.assertEqual(set(workflow.recommendation.action_ids), {"revoke-deploy", "revoke-backup"})
            self.assertEqual(workflow.approval.status, "pending")
            self.assertEqual(workflow.execute().actions_applied, ())
            self.assertIn("confidence=", workflow.audit_events[0].details)
            workflow.record_approval(True, "Demo analyst")
            self.assertTrue(workflow.execute().containment_verified)


if __name__ == "__main__":
    unittest.main()
