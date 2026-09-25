"""Simulation-only containment analysis for the small synthetic environment."""

from copy import deepcopy
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Iterable, Optional

from src.graph import AttackGraph


@dataclass(frozen=True)
class ContainmentAction:
    id: str
    name: str
    action_type: str
    target_entity: str
    operational_cost: int
    description: str
    requires_approval: bool = True


@dataclass
class ContainmentResult:
    actions: tuple[ContainmentAction, ...]
    paths_before: int
    paths_after: int
    paths_broken: int
    broken_paths: list[list[str]]
    remaining_paths: list[list[str]]
    containment_complete: bool
    operational_cost: int


def candidate_actions(graph: AttackGraph) -> list[ContainmentAction]:
    """Demo costs are relative disruption units, not measured business costs."""
    actions = [
        ContainmentAction("disable-alice", "Disable Alice account", "disable_account",
                          "alice", 5, "Interrupt Alice's access to enterprise services."),
        ContainmentAction("isolate-laptop", "Isolate Alice-Laptop", "isolate_host",
                          "alice-laptop", 8, "Disconnect Alice's workstation."),
        ContainmentAction("isolate-dev", "Isolate Dev-Server", "isolate_host",
                          "dev-server", 20, "Interrupt shared development workloads."),
        ContainmentAction("revoke-deploy", "Revoke Deployment Token", "revoke_credential",
                          "deploy-token", 1, "Interrupt token-based deployments."),
        ContainmentAction("revoke-backup", "Revoke Backup Service Token", "revoke_credential",
                          "backup-token", 2, "Interrupt token-based backups."),
        ContainmentAction("disable-deploy", "Disable Deployment Service", "disable_service",
                          "deploy-service", 10, "Stop the deployment service."),
        ContainmentAction("disable-backup", "Disable Backup Service", "disable_service",
                          "backup-service", 12, "Stop the backup service."),
    ]
    return [action for action in actions
            if action.target_entity in graph.entities
            and action.target_entity != graph.protected_asset]


def apply_actions_to_copy(
    graph: AttackGraph, actions: Iterable[ContainmentAction]
) -> AttackGraph:
    """Low-level simulation primitive; never modifies the supplied graph."""
    actions = tuple(sorted(actions, key=lambda action: action.id))
    if len({action.id for action in actions}) != len(actions):
        raise ValueError("Action IDs must be unique.")
    for action in actions:
        if action.target_entity == graph.protected_asset:
            raise ValueError("The protected asset cannot be a containment target.")
        if action.target_entity not in graph.entities:
            raise ValueError("Unknown containment target: " + action.target_entity)
        if action.operational_cost < 0:
            raise ValueError("Operational costs must be nonnegative.")

    simulated = deepcopy(graph)
    targets = {action.target_entity for action in actions}
    for target in targets:
        del simulated.entities[target]
    simulated.relationships = [
        relationship for relationship in simulated.relationships
        if relationship.source not in targets and relationship.target not in targets
    ]
    for source in list(simulated.adjacency):
        if source in targets:
            del simulated.adjacency[source]
        else:
            simulated.adjacency[source] = [
                (target, kind) for target, kind in simulated.adjacency[source]
                if target not in targets
            ]

    return simulated


def simulate_containment(
    graph: AttackGraph, actions: Iterable[ContainmentAction]
) -> ContainmentResult:
    """Remove targets and incident edges from a copy, then rerun path analysis."""
    actions = tuple(sorted(actions, key=lambda action: action.id))
    simulated = apply_actions_to_copy(graph, actions)
    before = graph.find_attack_paths(graph.compromised_entity, graph.protected_asset)
    remaining = simulated.find_attack_paths(
        simulated.compromised_entity, simulated.protected_asset
    )
    remaining_ids = {tuple(path) for path in remaining}
    broken = [path for path in before if tuple(path) not in remaining_ids]
    return ContainmentResult(
        actions=actions, paths_before=len(before), paths_after=len(remaining),
        paths_broken=len(broken), broken_paths=broken, remaining_paths=remaining,
        containment_complete=not remaining,
        operational_cost=sum(action.operational_cost for action in actions),
    )


def evaluate_actions(
    graph: AttackGraph, actions: Iterable[ContainmentAction]
) -> list[ContainmentResult]:
    return [simulate_containment(graph, [action]) for action in actions]


def recommend_containment(
    graph: AttackGraph, actions: Iterable[ContainmentAction]
) -> Optional[ContainmentResult]:
    """Minimize total cost, then action count, then sorted IDs across all subsets.

    Exhaustive search is intentional for this small demo. None means no supplied
    combination contains the incident; an empty action set means already safe.
    """
    actions = tuple(sorted(actions, key=lambda action: action.id))
    # Validate the entire candidate set even when no containment is necessary.
    simulate_containment(graph, actions)
    baseline = simulate_containment(graph, [])
    if baseline.containment_complete:
        return baseline

    best = None
    best_key = None
    for size in range(1, len(actions) + 1):
        for combination in combinations(actions, size):
            result = simulate_containment(graph, combination)
            key = (result.operational_cost, size, tuple(a.id for a in combination))
            if result.containment_complete and (best_key is None or key < best_key):
                best, best_key = result, key
    return best


def main() -> None:
    graph = AttackGraph()
    graph.load_environment(Path(__file__).resolve().parents[1] / "data" / "environment.json")
    actions = candidate_actions(graph)
    before = graph.find_attack_paths(graph.compromised_entity, graph.protected_asset)
    print("CHAINBREAK - CONTAINMENT ANALYSIS")
    print("Simulation only. Recommendation is not execution; actions require human approval.")
    print(f"Attack paths before containment: {len(before)}")
    for result in evaluate_actions(graph, actions):
        action = result.actions[0]
        print(f"\n{action.name} | Operational cost: {result.operational_cost}")
        print(f"Requires human approval: {action.requires_approval}")
        print(f"Paths broken: {result.paths_broken}")
        for path in result.broken_paths:
            print(f"  Broken: {graph.describe_path(path)}")
        print(f"Paths remaining: {result.paths_after}")
        for path in result.remaining_paths:
            print(f"  Remaining: {graph.describe_path(path)}")
        print("Containment: " + ("COMPLETE" if result.containment_complete else "INCOMPLETE"))

    print("\nRECOMMENDED CONTAINMENT")
    recommendation = recommend_containment(graph, actions)
    if recommendation is None:
        print("No candidate action or combination achieves complete containment.")
        print("Containment: INCOMPLETE")
        return
    print("Selected: " + (" + ".join(a.name for a in recommendation.actions)
                          or "No action needed"))
    print(f"Total operational cost: {recommendation.operational_cost}")
    print("Reason: Lowest total cost achieving complete containment across all candidate subsets.")
    print("Ties favor fewer actions, then sorted action IDs.")
    print(f"Paths before: {recommendation.paths_before}")
    print(f"Paths after: {recommendation.paths_after}")
    print("Containment: COMPLETE (simulated)")
    print("Recommendation only; human approval is required before any disruptive action.")


if __name__ == "__main__":
    main()
