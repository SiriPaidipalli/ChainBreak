import unittest
from pathlib import Path

from src.graph import AttackGraph


ENVIRONMENT_PATH = Path(__file__).resolve().parents[1] / "data" / "environment.json"


class AttackGraphTests(unittest.TestCase):
    def setUp(self):
        self.graph = AttackGraph()
        self.graph.load_environment(ENVIRONMENT_PATH)

    def attack_paths(self):
        return self.graph.find_attack_paths(
            self.graph.compromised_entity, self.graph.protected_asset
        )

    def test_environment_loads(self):
        self.assertEqual(len(self.graph.entities), 8)
        self.assertEqual(len(self.graph.relationships), 8)
        self.assertEqual(self.graph.compromised_entity, "alice")
        self.assertEqual(self.graph.protected_asset, "customer-db")
        self.assertEqual(self.graph.entities["customer-db"].criticality, "critical")

    def test_protected_asset_is_reachable(self):
        self.assertTrue(self.attack_paths())

    def test_multiple_expected_paths_terminate_at_protected_asset(self):
        paths = self.attack_paths()
        self.assertEqual(len(paths), 2)
        self.assertEqual(
            {tuple(path) for path in paths},
            {
                ("alice", "alice-laptop", "dev-server", "deploy-token",
                 "deploy-service", "customer-db"),
                ("alice", "alice-laptop", "dev-server", "backup-token",
                 "backup-service", "customer-db"),
            },
        )
        for path in paths:
            self.assertEqual(path[-1], self.graph.protected_asset)

    def test_cycles_do_not_repeat_entities_or_hide_paths(self):
        self.graph.adjacency["dev-server"].append(("alice", "can_access"))
        paths = self.attack_paths()
        self.assertEqual(len(paths), 2)
        for path in paths:
            self.assertEqual(len(path), len(set(path)))

    def test_unreachable_target_returns_no_paths(self):
        self.assertEqual(self.graph.find_attack_paths("customer-db", "alice"), [])

    def test_parallel_relationships_do_not_duplicate_entity_paths(self):
        self.graph.adjacency["alice"].append(("alice-laptop", "can_access"))
        self.assertEqual(len(self.attack_paths()), 2)

    def test_path_description_uses_entity_names(self):
        self.assertEqual(
            self.graph.describe_path(self.attack_paths()[0]),
            "Alice -> Alice-Laptop -> Dev-Server -> Deployment Token"
            " -> Deployment Service -> Customer Database",
        )


if __name__ == "__main__":
    unittest.main()
