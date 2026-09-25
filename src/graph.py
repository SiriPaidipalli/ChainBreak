import json
from collections import defaultdict, deque
from pathlib import Path

from src.models import Entity, Relationship


class AttackGraph:
    def __init__(self):
        self.entities = {}
        self.relationships = []
        self.adjacency = defaultdict(list)

    def load_environment(self, file_path):
        with open(file_path, "r") as file:
            data = json.load(file)

        for item in data["entities"]:
            entity = Entity(
                id=item["id"],
                type=item["type"],
                name=item["name"],
                criticality=item.get("criticality")
            )
            self.entities[entity.id] = entity

        for item in data["relationships"]:
            relationship = Relationship(
                source=item["source"],
                target=item["target"],
                type=item["type"]
            )

            self.relationships.append(relationship)

            self.adjacency[relationship.source].append(
                (relationship.target, relationship.type)
            )

        self.protected_asset = data["protected_asset"]
        self.compromised_entity = data["incident"]["compromised_entity"]

    def find_attack_paths(self, start: str, target: str) -> list[list[str]]:
        """Return all distinct simple paths along directed relationships.

        Each path is an ordered list of entity IDs, including both endpoints.
        Entities cannot repeat within a path. An unreachable target returns [].
        """
        if start not in self.entities or target not in self.entities:
            return []

        queue = deque([(start, [start])])
        paths = []

        while queue:
            current, path = queue.popleft()

            if current == target:
                paths.append(path)
                continue

            # Multiple relationships to the same entity define one entity path.
            neighbors = dict.fromkeys(
                neighbor for neighbor, _ in self.adjacency.get(current, [])
            )
            for neighbor in neighbors:
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def find_attack_path(self, start, target):
        """Keep the original single-path interface available for callers."""
        paths = self.find_attack_paths(start, target)
        return paths[0] if paths else None

    def describe_path(self, path):
        if not path:
            return "No viable attack path found."

        return " -> ".join(
            self.entities[entity_id].name
            for entity_id in path
        )


if __name__ == "__main__":
    graph = AttackGraph()

    environment_path = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "environment.json"
    )

    graph.load_environment(environment_path)

    paths = graph.find_attack_paths(
        graph.compromised_entity,
        graph.protected_asset
    )

    print("\nCHAINBREAK - ATTACK PATH ANALYSIS")
    print("---------------------------------")
    print(f"Compromised entity: {graph.entities[graph.compromised_entity].name}")
    print(f"Protected asset:    {graph.entities[graph.protected_asset].name}")
    print(f"Viable attack paths: {len(paths)}")
    print()

    if paths:
        print("STATUS: PROTECTED ASSET REACHABLE")
        for number, path in enumerate(paths, start=1):
            print(f"Attack path {number}: {graph.describe_path(path)}")
    else:
        print("STATUS: NO ATTACK PATH FOUND")
