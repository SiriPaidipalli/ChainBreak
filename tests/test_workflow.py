import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from src.containment import candidate_actions
from src.graph import AttackGraph
from src.workflow import ContainmentWorkflow


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.graph = AttackGraph()
        self.graph.load_environment(
            Path(__file__).resolve().parents[1] / "data" / "environment.json"
        )
        self.original = deepcopy(self.graph.__dict__)

    def test_missing_approval_blocks_execution(self):
        workflow = ContainmentWorkflow(self.graph)
        result = workflow.execute()
        self.assertEqual(workflow.approval.status, "pending")
        self.assertEqual(result.actions_applied, ())
        self.assertEqual(result.paths_after, 2)
        self.assertFalse(result.containment_verified)
        self.assertEqual(workflow.post_containment_graph.__dict__, self.original)
        self.assertIn("execution_blocked", [e.event_type for e in workflow.audit_events])

    def test_denied_approval_changes_neither_graph(self):
        workflow = ContainmentWorkflow(self.graph)
        approval = workflow.record_approval(False, "Analyst", "Investigate first")
        result = workflow.execute()
        self.assertEqual(approval.status, "denied")
        self.assertEqual(approval.approver, "Analyst")
        self.assertEqual(approval.note, "Investigate first")
        self.assertEqual(approval.recommendation_id, workflow.recommendation.id)
        self.assertEqual(approval.action_ids, workflow.recommendation.action_ids)
        self.assertTrue(approval.timestamp)
        self.assertEqual(result.actions_applied, ())
        self.assertEqual(workflow.post_containment_graph.__dict__, self.original)
        self.assertEqual(self.graph.__dict__, self.original)

    def test_approved_combination_verifies_on_separate_graph(self):
        workflow = ContainmentWorkflow(self.graph)
        workflow.record_approval(True, "Analyst")
        result = workflow.execute()
        self.assertEqual(result.paths_before, 2)
        self.assertEqual(result.paths_after, 0)
        self.assertTrue(result.containment_verified)
        self.assertEqual(result.remaining_paths, [])
        self.assertEqual(set(result.actions_applied), {"revoke-backup", "revoke-deploy"})
        self.assertIsNot(workflow.post_containment_graph, self.graph)
        self.assertNotIn("deploy-token", workflow.post_containment_graph.entities)
        self.assertNotIn("backup-token", workflow.post_containment_graph.entities)
        self.assertEqual(self.graph.__dict__, self.original)
        workflow.post_containment_graph.entities["alice"].name = "Changed copy"
        self.assertEqual(self.graph.entities["alice"].name, "Alice")

    def test_partial_action_returns_surviving_alternate_path(self):
        actions = [a for a in candidate_actions(self.graph) if a.id == "revoke-deploy"]
        workflow = ContainmentWorkflow(self.graph, actions)
        workflow.record_approval(True, "Analyst")
        result = workflow.execute()
        self.assertFalse(result.containment_verified)
        self.assertEqual(result.paths_before, 2)
        self.assertEqual(result.paths_after, 1)
        self.assertEqual(result.actions_applied, ("revoke-deploy",))
        self.assertEqual(result.remaining_paths, [[
            "alice", "alice-laptop", "dev-server", "backup-token",
            "backup-service", "customer-db",
        ]])
        self.assertEqual(self.graph.describe_path(result.remaining_paths[0]),
                         "Alice -> Alice-Laptop -> Dev-Server -> Backup Service Token"
                         " -> Backup Service -> Customer Database")

    def test_verification_does_not_trust_prediction_when_execution_is_ineffective(self):
        workflow = ContainmentWorkflow(self.graph)
        self.assertEqual(workflow.recommendation.predicted_paths_after, 0)
        workflow.record_approval(True, "Analyst")
        with patch("src.workflow.apply_actions_to_copy", return_value=deepcopy(self.graph)):
            result = workflow.execute()
        self.assertEqual(result.paths_after, 2)
        self.assertFalse(result.containment_verified)
        self.assertEqual(len(result.remaining_paths), 2)
        self.assertEqual(workflow.audit_events[-1].status, "incomplete")

    def test_audit_is_ordered_retained_and_read_only(self):
        workflow = ContainmentWorkflow(self.graph)
        initial = workflow.audit_events
        workflow.record_approval(False, "First analyst")
        workflow.execute()
        denied = workflow.audit_events
        workflow.record_approval(True, "Second analyst")
        workflow.execute()
        events = workflow.audit_events
        self.assertEqual(events[:len(initial)], initial)
        self.assertEqual(events[:len(denied)], denied)
        self.assertEqual([e.event_type for e in events], [
            "incident_analyzed", "recommendation_generated", "approval_denied",
            "execution_blocked", "verification_performed", "approval_granted",
            "simulated_action_applied", "simulated_action_applied", "verification_performed",
        ])
        self.assertEqual([e.timestamp for e in events], sorted(e.timestamp for e in events))
        self.assertTrue(all(e.status and e.details for e in events))
        with self.assertRaises(FrozenInstanceError):
            events[0].status = "edited"
        with self.assertRaises(AttributeError):
            workflow.audit_events = ()

    def test_approval_requires_named_analyst_and_boolean_decision(self):
        workflow = ContainmentWorkflow(self.graph)
        for granted, name in [(True, " "), ("yes", "Analyst")]:
            with self.assertRaises(ValueError):
                workflow.record_approval(granted, name)
        self.assertEqual(workflow.approval.status, "pending")

    def test_mismatched_approval_cannot_authorize_execution(self):
        for field in [{"recommendation_id": "other"}, {"action_ids": ("revoke-deploy",)}]:
            workflow = ContainmentWorkflow(self.graph)
            approval = workflow.record_approval(True, "Analyst")
            # Deliberately inject a stale/mismatched record to exercise the guard.
            workflow._approval = replace(approval, **field)
            self.assertEqual(workflow.execute().actions_applied, ())
            self.assertEqual(workflow.post_containment_graph.__dict__, self.original)

    def test_proposal_and_approval_are_immutable(self):
        workflow = ContainmentWorkflow(self.graph)
        with self.assertRaises(FrozenInstanceError):
            workflow.recommendation.actions = ()
        with self.assertRaises(FrozenInstanceError):
            workflow.approval.status = "granted"

    def test_successful_workflow_cannot_execute_twice(self):
        workflow = ContainmentWorkflow(self.graph)
        workflow.record_approval(True, "Analyst")
        workflow.execute()
        with self.assertRaises(ValueError):
            workflow.execute()
        with self.assertRaises(ValueError):
            workflow.record_approval(True, "Other analyst")


if __name__ == "__main__":
    unittest.main()
