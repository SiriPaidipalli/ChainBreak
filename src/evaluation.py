"""Repeatable local security scenarios; observations come from existing backends."""

import json
from copy import deepcopy
from pathlib import Path

from src.containment import candidate_actions, evaluate_actions
from src.graph import AttackGraph
from src.incident import SecurityEvent, analyze_incident, load_events, missing_telemetry_events
from src.workflow import ContainmentWorkflow

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "data" / "evaluation" / "scenarios.json"
RESULTS = ROOT / "evaluation_results.json"


def load_scenario(spec):
    graph = AttackGraph()
    graph.load_environment(ROOT / "data" / "environment.json")
    removed = {tuple(edge) for edge in spec["remove_edges"]}
    graph.relationships = [r for r in graph.relationships if (r.source, r.target) not in removed]
    for source in graph.adjacency:
        graph.adjacency[source] = [(target, kind) for target, kind in graph.adjacency[source]
                                   if (source, target) not in removed]
    events = load_events()
    if spec["telemetry"] == "none":
        events = []
    elif spec["telemetry"] == "missing":
        events = missing_telemetry_events(events)
    elif spec["telemetry"] == "suspicious":
        events = [SecurityEvent(
            "eval-suspicious-001", "2026-09-25T09:00:00Z", "synthetic_identity_log",
            "unusual_identity_login", "alice", "alice", "high",
            "Alice's identity logged in from an unfamiliar source; database routes are unavailable.",
        )]
    return graph, events


def evaluate_scenario(spec):
    graph, events = load_scenario(spec)
    original = deepcopy(graph.__dict__)
    analysis = analyze_incident(graph, events)
    workflow = ContainmentWorkflow(graph, events=events)
    proposal = workflow.recommendation
    checks = {}
    observed = {
        "viable_paths_before": len(analysis.paths),
        "protected_asset_reachable": bool(analysis.paths),
        "evidence_count": len(analysis.evidence),
        "evidence_coverage": analysis.evidence_coverage,
        "confidence": analysis.confidence,
        "telemetry_incomplete": analysis.telemetry_incomplete,
        "recommended_action_ids": list(proposal.action_ids) if proposal else [],
        "recommended_cost": proposal.operational_cost if proposal else None,
        "operational_cost": proposal.operational_cost if proposal else None,
        "disruptive_containment_recommended": bool(proposal and proposal.actions),
        "analyst_approval_required": bool(proposal and proposal.actions),
        "actions_applied": [],
        "containment_status": "NOT EXECUTED",
    }
    kind = spec["kind"]
    if kind in {"normal", "negative"}:
        checks["asset_unreachable"] = not observed["protected_asset_reachable"]
        checks["no_disruptive_recommendation"] = not observed["disruptive_containment_recommended"]
        result = workflow.execute()  # Pending approval must cause a no-op.
        observed["actions_applied"] = list(result.actions_applied)
        checks["no_response"] = not result.actions_applied
        observed["viable_paths_after"] = result.paths_after
        observed["containment_status"] = "NOT REQUIRED" if not analysis.paths else "INCOMPLETE"
        if kind == "negative":
            checks["suspicious_evidence_present"] = any(e.severity == "high" for e in analysis.evidence)
    elif kind == "missing":
        full = analyze_incident(graph, load_events())
        observed["full_evidence_coverage"] = full.evidence_coverage
        observed["full_confidence"] = full.confidence
        checks["paths_reconstructed"] = len(analysis.paths) == len(full.paths) == 2
        checks["coverage_lower"] = analysis.evidence_coverage < full.evidence_coverage
        checks["confidence_lower"] = analysis.confidence < full.confidence
        checks["missing_explicit"] = analysis.telemetry_incomplete
        retained = {e.event_id for e in events}
        checks["no_invented_evidence"] = all(
            event_id in retained for path in analysis.paths
            for ids in path.transition_evidence.values() for event_id in ids
        ) and {e.event_id for e in analysis.evidence}.issubset(retained)
        result = workflow.execute()
        observed["actions_applied"] = list(result.actions_applied)
        observed["viable_paths_after"] = result.paths_after
        checks["no_unapproved_response"] = not result.actions_applied and result.paths_after == 2
    elif kind in {"positive", "success", "partial"}:
        checks["two_initial_paths"] = len(analysis.paths) == 2
        checks["both_paths_evidenced"] = all(p.supported_transitions > 0 for p in analysis.paths)
        if kind == "partial":
            actions = [a for a in candidate_actions(graph) if a.id == "revoke-deploy"]
            workflow = ContainmentWorkflow(graph, selected_actions=actions, events=events)
            observed["operational_cost"] = workflow.recommendation.operational_cost
        else:
            checks["computed_token_recommendation"] = bool(proposal) and set(proposal.action_ids) == {"revoke-backup", "revoke-deploy"}
            checks["cost_three"] = bool(proposal) and proposal.operational_cost == 3
        blocked = workflow.execute()
        checks["approval_enforced"] = (
            not blocked.actions_applied and blocked.paths_after == 2
            and workflow.post_containment_graph.__dict__ == original
            and any(e.event_type == "execution_blocked" for e in workflow.audit_events)
        )
        approval = workflow.record_approval(True, "SOC-Analyst", "Security evaluation; simulation only.")
        observed["approved_action_ids"] = list(approval.action_ids)
        observed["approval_status"] = approval.status
        checks["explicit_matching_approval"] = (
            approval.status == "granted" and approval.approver == "SOC-Analyst"
            and approval.action_ids == workflow.recommendation.action_ids
            and approval.recommendation_id == workflow.recommendation.id
        )
        result = workflow.execute()
        observed.update(viable_paths_after=result.paths_after,
                        actions_applied=list(result.actions_applied),
                        containment_status="VERIFIED" if result.containment_verified else "INCOMPLETE",
                        remaining_paths=result.remaining_paths,
                        remaining_routes=[graph.describe_path(path) for path in result.remaining_paths])
        checks["copied_graph"] = workflow.post_containment_graph is not graph
        checks["recalculated_result"] = result.remaining_paths == workflow.post_containment_graph.find_attack_paths(
            graph.compromised_entity, graph.protected_asset)
        if kind == "partial":
            expected = ["alice", "alice-laptop", "dev-server", "backup-token", "backup-service", "customer-db"]
            checks["only_deployment_revoked"] = result.actions_applied == ("revoke-deploy",)
            checks["alternate_route_survives"] = result.paths_after == 1 and result.remaining_paths == [expected]
            checks["explicitly_incomplete"] = not result.containment_verified
        else:
            checks["approved_actions_applied"] = result.actions_applied == proposal.action_ids
            checks["verified_zero_paths"] = result.containment_verified and result.paths_after == 0
    elif kind == "comparison":
        alternatives = [r for r in evaluate_actions(graph, candidate_actions(graph))
                        if r.actions[0].id in {"disable-alice", "isolate-laptop", "isolate-dev"}]
        observed["alternatives"] = [
            {"action": r.actions[0].name, "operational_cost": r.operational_cost,
             "paths_after": r.paths_after, "containment_complete": r.containment_complete,
             "cost_reduction": r.operational_cost - proposal.operational_cost,
             "reduction_percent": round(100 * (r.operational_cost - proposal.operational_cost) / r.operational_cost, 1)}
            for r in alternatives
        ]
        checks["three_complete_alternatives"] = len(alternatives) == 3 and all(r.containment_complete for r in alternatives)
        checks["recommendation_cheaper_and_complete"] = proposal.predicted_paths_after == 0 and all(
            proposal.operational_cost < r.operational_cost for r in alternatives)
    else:
        raise ValueError("Unknown scenario kind: " + kind)

    observed["original_graph_unchanged"] = graph.__dict__ == original
    observed["protected_asset_preserved"] = (
        graph.entities[graph.protected_asset] == workflow.post_containment_graph.entities.get(graph.protected_asset))
    checks["original_unchanged"] = observed["original_graph_unchanged"]
    checks["asset_preserved"] = observed["protected_asset_preserved"]
    return {"scenario": spec["name"], "expected_behavior": spec["expected"],
            "observed": observed, "checks": checks, "passed": all(checks.values())}


def run_evaluation():
    with SCENARIOS.open(encoding="utf-8") as file:
        specs = json.load(file)
    scenarios = []
    for spec in specs:
        try:
            scenarios.append(evaluate_scenario(spec))
        except Exception as error:
            scenarios.append({"scenario": spec["name"], "expected_behavior": spec["expected"],
                              "observed": {"error": f"{type(error).__name__}: {error}"},
                              "checks": {"completed_without_error": False}, "passed": False})
    passed = sum(result["passed"] for result in scenarios)
    return {"scenarios": scenarios, "scenarios_passed": passed,
            "scenarios_total": len(scenarios), "overall_passed": bool(scenarios) and passed == len(scenarios)}


def write_results(results, path=RESULTS):
    Path(path).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    results = run_evaluation()
    write_results(results)
    print("CHAINBREAK SECURITY EVALUATION\n==============================")
    for scenario in results["scenarios"]:
        print(f"\n[{'PASS' if scenario['passed'] else 'FAIL'}] {scenario['scenario']}")
        observed = scenario["observed"]
        for key in ("protected_asset_reachable", "evidence_count", "viable_paths_before",
                    "viable_paths_after", "evidence_coverage", "confidence", "telemetry_incomplete", "operational_cost",
                    "disruptive_containment_recommended", "containment_status", "remaining_routes", "error"):
            if key in observed:
                print(f"  {key.replace('_', ' ').capitalize()}: {observed[key]}")
        for alternative in observed.get("alternatives", []):
            print(f"  {alternative['action']}: cost {alternative['operational_cost']}; "
                  f"{alternative['paths_after']} paths remain; recommendation reduces cost "
                  f"by {alternative['reduction_percent']}%")
        for name, passed in scenario["checks"].items():
            if not passed:
                print(f"  Failed check: {name}")
    print(f"\nScenarios passed: {results['scenarios_passed']}/{results['scenarios_total']}")
    print("Overall evaluation: " + ("PASS" if results["overall_passed"] else "FAIL"))
    print(f"Results: {RESULTS}")
    return 0 if results["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
