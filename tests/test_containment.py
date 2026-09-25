import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from src.containment import (
    candidate_actions, evaluate_actions, recommend_containment, simulate_containment,
)
from src.graph import AttackGraph


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.graph = AttackGraph()
        self.graph.load_environment(
            Path(__file__).resolve().parents[1] / "data" / "environment.json"
        )
        self.actions = candidate_actions(self.graph)
        self.by_id = {action.id: action for action in self.actions}

    def test_analysis_does_not_mutate_original_graph(self):
        original = deepcopy(self.graph.__dict__)
        evaluate_actions(self.graph, self.actions)
        recommend_containment(self.graph, self.actions)
        self.assertEqual(self.graph.__dict__, original)

    def test_each_token_revocation_leaves_alternate_path(self):
        for action_id, surviving_token, surviving_service in [
            ("revoke-deploy", "backup-token", "backup-service"),
            ("revoke-backup", "deploy-token", "deploy-service"),
        ]:
            with self.subTest(action=action_id):
                result = simulate_containment(self.graph, [self.by_id[action_id]])
                self.assertEqual(result.paths_before, 2)
                self.assertEqual(result.paths_after, 1)
                self.assertEqual(result.paths_broken, 1)
                self.assertFalse(result.containment_complete)
                self.assertEqual(result.remaining_paths, [[
                    "alice", "alice-laptop", "dev-server", surviving_token,
                    surviving_service, "customer-db",
                ]])
                self.assertIn(self.by_id[action_id].target_entity, result.broken_paths[0])

    def test_shared_node_removal_completely_contains_incident(self):
        for action_id in ["disable-alice", "isolate-laptop", "isolate-dev"]:
            with self.subTest(action=action_id):
                result = simulate_containment(self.graph, [self.by_id[action_id]])
                self.assertTrue(result.containment_complete)
                self.assertEqual(result.paths_broken, 2)
                self.assertEqual(result.paths_after, 0)
                self.assertEqual(result.remaining_paths, [])

    def test_every_candidate_is_evaluated(self):
        results = evaluate_actions(self.graph, self.actions)
        self.assertEqual(len(results), 7)
        self.assertEqual({r.actions[0].id for r in results}, set(self.by_id))
        for result in results:
            self.assertEqual(result.operational_cost, result.actions[0].operational_cost)

    def test_lowest_cost_complete_single_action_selected(self):
        actions = [self.by_id[key] for key in ["isolate-dev", "isolate-laptop", "disable-alice"]]
        result = recommend_containment(self.graph, actions)
        self.assertEqual([a.id for a in result.actions], ["disable-alice"])
        self.assertEqual(result.operational_cost, 5)

    def test_cheaper_combination_beats_complete_single_actions(self):
        result = recommend_containment(self.graph, self.actions)
        self.assertEqual({a.id for a in result.actions}, {"revoke-deploy", "revoke-backup"})
        self.assertEqual(result.operational_cost, 3)
        self.assertTrue(result.containment_complete)
        self.assertEqual(result.paths_after, 0)

    def test_combination_found_when_no_single_action_completes_containment(self):
        actions = [self.by_id["revoke-deploy"], self.by_id["revoke-backup"]]
        self.assertTrue(all(not r.containment_complete for r in evaluate_actions(self.graph, actions)))
        self.assertTrue(recommend_containment(self.graph, actions).containment_complete)

    def test_no_complete_combination_returns_none(self):
        self.assertIsNone(recommend_containment(self.graph, [self.by_id["revoke-deploy"]]))
        self.assertIsNone(recommend_containment(self.graph, []))

    def test_cost_changes_change_recommendation(self):
        actions = [replace(a, operational_cost=0) if a.id == "isolate-dev" else a
                   for a in self.actions]
        result = recommend_containment(self.graph, actions)
        self.assertEqual([a.id for a in result.actions], ["isolate-dev"])

    def test_ties_prefer_fewer_actions_then_ids_regardless_of_input_order(self):
        actions = [replace(self.by_id["disable-alice"], operational_cost=3),
                   replace(self.by_id["isolate-dev"], operational_cost=3),
                   self.by_id["revoke-deploy"], self.by_id["revoke-backup"]]
        for ordered in [actions, list(reversed(actions))]:
            result = recommend_containment(self.graph, ordered)
            self.assertEqual([a.id for a in result.actions], ["disable-alice"])

    def test_protected_asset_never_proposed_and_cannot_be_removed(self):
        self.assertNotIn(self.graph.protected_asset, [a.target_entity for a in self.actions])
        invalid = replace(self.actions[0], target_entity=self.graph.protected_asset)
        with self.assertRaises(ValueError):
            simulate_containment(self.graph, [invalid])
        self.graph.protected_asset = "dev-server"
        self.assertNotIn("dev-server", [a.target_entity for a in candidate_actions(self.graph)])

    def test_all_candidates_require_approval(self):
        self.assertTrue(all(a.requires_approval for a in self.actions))

    def test_already_unreachable_requires_no_action(self):
        self.graph.adjacency["alice"] = []
        result = recommend_containment(self.graph, self.actions)
        self.assertEqual(result.actions, ())
        self.assertEqual(result.operational_cost, 0)
        self.assertEqual(result.paths_before, 0)
        self.assertTrue(result.containment_complete)

    def test_invalid_candidates_are_rejected(self):
        for invalid in [replace(self.actions[0], target_entity="missing"),
                        replace(self.actions[0], operational_cost=-1)]:
            with self.assertRaises(ValueError):
                recommend_containment(self.graph, [invalid])
        with self.assertRaises(ValueError):
            recommend_containment(self.graph, [self.actions[0], self.actions[0]])


if __name__ == "__main__":
    unittest.main()
