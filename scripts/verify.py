"""Run ChainBreak's tests and state-based demo checks using only the standard library."""

import io
import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.containment import candidate_actions
from src.graph import AttackGraph
from src.incident import analyze_incident, load_events
from src.workflow import ContainmentWorkflow


class ExternalActionGuard:
    """Reject network/process activity during verification, including caught attempts.

    Python audit hooks cover the standard-library network and process entry points
    used by this project. This is a regression guard, not an OS security sandbox.
    """

    def __init__(self):
        self.active = False
        self.attempts = []

    def audit(self, event, args):
        if self.active and (event.startswith("socket.") or event in {
            "subprocess.Popen", "os.system", "os.posix_spawn", "os.spawn",
            "os.exec", "os.fork", "os.forkpty",
        }):
            self.attempts.append(event)
            raise RuntimeError("External action blocked: " + event)


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def main() -> int:
    reports = []
    guard = ExternalActionGuard()
    sys.addaudithook(guard.audit)
    guard.active = True
    graphs = []
    workflows = []

    def check(name, operation):
        try:
            detail = operation()
            reports.append((name, True, detail or ""))
        except Exception as error:
            reports.append((name, False, f"{type(error).__name__}: {error}"))

    def fresh_graph():
        graph = AttackGraph()
        graph.load_environment(ROOT / "data" / "environment.json")
        graphs.append((graph, deepcopy(graph.__dict__)))
        return graph

    def workflow_for(graph, actions=None):
        workflow = ContainmentWorkflow(graph, selected_actions=actions)
        workflows.append(workflow)
        return workflow

    def approve(workflow):
        approval = workflow.record_approval(True, "SOC-Analyst", "Automated simulation verification.")
        require(approval.status == "granted" and approval.approver == "SOC-Analyst",
                "Analyst approval was not recorded")
        require(approval.recommendation_id == workflow.recommendation.id
                and approval.action_ids == workflow.recommendation.action_ids,
                "Approval does not match the proposal")

    def unit_tests():
        stream = io.StringIO()
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
        result = unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)
        require(result.testsRun > 0, "No unit tests discovered")
        require(result.wasSuccessful(), stream.getvalue().strip())
        return f"{result.testsRun} tests passed"

    def incident():
        result = analyze_incident(fresh_graph(), load_events())
        require(bool(result.evidence), "No incident evidence loaded")
        require(len(result.paths) == 2 and all(p.supported_transitions > 0 for p in result.paths),
                "Both attack paths must have evidence")
        require(0 <= result.risk_score <= 100, "Risk score outside 0–100")

    def attack_paths():
        graph = fresh_graph()
        paths = graph.find_attack_paths(graph.compromised_entity, graph.protected_asset)
        require(len(paths) == 2, f"Expected 2 paths, found {len(paths)}")
        require(all(p[0] == graph.compromised_entity and p[-1] == graph.protected_asset for p in paths),
                "Incorrect attack-path endpoints")

    def recommendation():
        workflow = workflow_for(fresh_graph())
        proposal = workflow.recommendation
        require(proposal is not None, "No containment recommendation")
        require(set(proposal.action_ids) == {"revoke-backup", "revoke-deploy"},
                "Unexpected recommended actions")
        require(proposal.operational_cost == 3, "Expected total operational cost 3")
        require(all(a.requires_approval for a in proposal.actions), "Approval requirement missing")

    def approval_enforcement():
        for denied in (False, True):
            graph = fresh_graph()
            workflow = workflow_for(graph)
            if denied:
                workflow.record_approval(False, "SOC-Analyst")
            result = workflow.execute()
            require(not result.actions_applied and result.paths_after == 2
                    and not result.containment_verified, "Unapproved actions executed")
            require(workflow.post_containment_graph.__dict__ == graph.__dict__,
                    "Unapproved execution changed the graph")
            require(any(e.event_type == "execution_blocked" for e in workflow.audit_events),
                    "Blocked execution missing from audit")

    def successful():
        graph = fresh_graph()
        workflow = workflow_for(graph)
        approve(workflow)
        result = workflow.execute()
        require(result.paths_before == 2 and result.paths_after == 0
                and result.containment_verified and not result.remaining_paths,
                "Approved recommendation did not verify 2 → 0 paths")
        require(result.actions_applied == workflow.recommendation.action_ids,
                "Applied actions differ from the approved proposal")
        require(not workflow.post_containment_graph.find_attack_paths(
            graph.compromised_entity, graph.protected_asset), "Post-action graph is still reachable")
        require(all(a.target_entity not in workflow.post_containment_graph.entities
                    for a in workflow.recommendation.actions), "Approved targets remain in simulated graph")
        applied = [e for e in workflow.audit_events if e.event_type == "simulated_action_applied"]
        require({i for e in applied for i in e.action_ids} == set(result.actions_applied),
                "Applied simulation actions missing from audit")

    def incomplete():
        graph = fresh_graph()
        actions = [a for a in candidate_actions(graph) if a.id == "revoke-deploy"]
        require(len(actions) == 1, "Deployment Token action missing")
        workflow = workflow_for(graph, actions)
        approve(workflow)
        result = workflow.execute()
        require(result.actions_applied == ("revoke-deploy",), "Unexpected partial-containment actions")
        require(result.paths_before == 2 and result.paths_after >= 1 and not result.containment_verified,
                "Partial containment incorrectly reported as complete")
        expected = ["alice", "alice-laptop", "dev-server", "backup-token", "backup-service", "customer-db"]
        require(expected in result.remaining_paths, "Surviving Backup Service path missing")
        require(result.remaining_paths == workflow.post_containment_graph.find_attack_paths(
            graph.compromised_entity, graph.protected_asset), "Remaining paths do not match actual reachability")
        require(workflow.audit_events[-1].status == "incomplete", "Incomplete result missing from audit")

    def integrity():
        require(bool(graphs) and bool(workflows), "No graph/workflow state available to inspect")
        for graph, original in graphs:
            require(graph.__dict__ == original, "Original graph was mutated")
            for workflow in workflows:
                require(workflow.post_containment_graph is not graph, "Simulation reused an original graph")

    def protected_asset():
        require(bool(workflows), "No workflow graphs available to inspect")
        for workflow in workflows:
            graph = workflow.post_containment_graph
            require(graph.protected_asset in graph.entities, "Protected asset removed")
            require(all(a.target_entity != graph.protected_asset
                        for a in workflow.recommendation.actions), "Protected asset proposed as a target")
        graph = fresh_graph()
        require(all(a.target_entity != graph.protected_asset for a in candidate_actions(graph)),
                "Candidate action targets the protected asset")

    try:
        for name, operation in [
            ("Unit tests", unit_tests),
            ("Incident analysis", incident),
            ("Attack paths detected", attack_paths),
            ("Containment recommendation", recommendation),
            ("Approval enforcement", approval_enforcement),
            ("Incomplete containment detection", incomplete),
            ("Successful containment verification", successful),
            ("Original graph integrity", integrity),
            ("Protected asset preserved", protected_asset),
        ]:
            check(name, operation)
        check("No external actions", lambda: require(
            not guard.attempts, "Blocked external action attempts: " + ", ".join(guard.attempts)))
    finally:
        guard.active = False

    print("## CHAINBREAK VERIFICATION\n")
    for name, passed, detail in reports:
        print(f"{name}: {'PASS' if passed else 'FAIL'}" + (f" — {detail}" if detail else ""))
    passed = all(passed for _, passed, _ in reports)
    print("\nOVERALL: " + ("PASS" if passed else "FAIL"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
