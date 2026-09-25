"""Explicitly approved, simulation-only SOC workflow with in-memory audit."""

import argparse
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional
from uuid import uuid4

from src.containment import (
    ContainmentAction, apply_actions_to_copy, candidate_actions,
    recommend_containment, simulate_containment,
)
from src.graph import AttackGraph
from src.incident import (
    DEFAULT_EVENTS, SecurityEvent, analyze_incident, load_events,
    missing_telemetry_events, print_incident_analysis,
)


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Recommendation:
    id: str
    actions: tuple[ContainmentAction, ...]
    operational_cost: int
    predicted_paths_after: int

    @property
    def action_ids(self) -> tuple[str, ...]:
        return tuple(action.id for action in self.actions)


@dataclass(frozen=True)
class Approval:
    recommendation_id: str
    action_ids: tuple[str, ...]
    status: str
    approver: Optional[str]
    timestamp: str
    note: Optional[str] = None


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    event_type: str
    recommendation_id: Optional[str]
    action_ids: tuple[str, ...]
    status: str
    details: str


@dataclass
class Verification:
    paths_before: int
    actions_applied: tuple[str, ...]
    paths_after: int
    containment_verified: bool
    remaining_paths: list[list[str]]


def verify_containment(
    graph: AttackGraph, paths_before: int, actions_applied: tuple[str, ...]
) -> Verification:
    """Recalculate actual post-action reachability without prediction metadata."""
    paths = graph.find_attack_paths(graph.compromised_entity, graph.protected_asset)
    return Verification(paths_before, actions_applied, len(paths), not paths, paths)


class ContainmentWorkflow:
    """One incident snapshot and one immutable proposal per workflow.

    Passing selected_actions creates a deliberate analyst proposal for demos.
    Otherwise the existing engine dynamically chooses the recommendation.
    """

    def __init__(self, graph: AttackGraph,
                 selected_actions: Optional[Iterable[ContainmentAction]] = None,
                 events: Optional[Iterable[SecurityEvent]] = None):
        self._baseline = deepcopy(graph)
        self._events: list[AuditEvent] = []
        self._executed = False
        self.post_containment_graph = deepcopy(self._baseline)
        self.incident_analysis = analyze_incident(
            self._baseline, load_events() if events is None else events
        )
        self.paths_before = len(self.incident_analysis.paths)
        self._record("incident_analyzed", "analyzed",
                     f"{self.paths_before} viable paths; "
                     f"evidence={len(self.incident_analysis.evidence)} events; "
                     f"risk={self.incident_analysis.risk_score}/100; "
                     f"confidence={self.incident_analysis.confidence}/100; "
                     f"telemetry_incomplete={self.incident_analysis.telemetry_incomplete}.")
        prediction = (
            recommend_containment(self._baseline, candidate_actions(self._baseline))
            if selected_actions is None
            else simulate_containment(self._baseline, selected_actions)
        )
        self._recommendation = None if prediction is None else Recommendation(
            str(uuid4()), prediction.actions, prediction.operational_cost,
            prediction.paths_after,
        )
        self._approval = None
        if self.recommendation is not None:
            self._approval = Approval(
                self.recommendation.id, self.recommendation.action_ids,
                "pending", None, timestamp(),
            )
        self._record(
            "recommendation_generated", "generated" if prediction is not None else "unavailable",
            "Computed minimum-cost proposal." if selected_actions is None
            else "Analyst-selected proposal for deliberate partial-containment simulation.",
        )

    @property
    def recommendation(self) -> Optional[Recommendation]:
        return self._recommendation

    @property
    def approval(self) -> Optional[Approval]:
        return self._approval

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        # Immutable snapshot: callers cannot append, remove, or edit past events.
        return tuple(self._events)

    def _record(self, event_type, status, details, action_ids=None):
        recommendation = getattr(self, "_recommendation", None)
        self._events.append(AuditEvent(
            timestamp(), event_type, recommendation.id if recommendation else None,
            action_ids if action_ids is not None else (
                recommendation.action_ids if recommendation else ()
            ), status, details,
        ))

    def record_approval(self, granted: bool, approver: str,
                        note: Optional[str] = None) -> Approval:
        if self._executed:
            raise ValueError("This workflow has already executed.")
        if self.recommendation is None:
            raise ValueError("There is no recommendation to approve.")
        if not isinstance(granted, bool) or not approver.strip():
            raise ValueError("Approval requires a boolean decision and named approver.")
        self._approval = Approval(
            self.recommendation.id, self.recommendation.action_ids,
            "granted" if granted else "denied", approver, timestamp(), note,
        )
        self._record("approval_granted" if granted else "approval_denied",
                     self.approval.status, f"Analyst: {approver}. {note or ''}".strip())
        return self.approval

    def execute(self) -> Verification:
        if self._executed:
            raise ValueError("This workflow has already executed.")
        recommendation, approval = self.recommendation, self.approval
        authorized = (
            recommendation is not None and approval is not None
            and approval.status == "granted"
            and approval.recommendation_id == recommendation.id
            and approval.action_ids == recommendation.action_ids
        )
        applied = ()
        if authorized:
            self.post_containment_graph = apply_actions_to_copy(
                self._baseline, recommendation.actions
            )
            self._executed = True
            applied = recommendation.action_ids
            for action in recommendation.actions:
                self._record("simulated_action_applied", "applied",
                             f"{action.name}; simulation only.", (action.id,))
        else:
            self.post_containment_graph = deepcopy(self._baseline)
            self._record("execution_blocked", "blocked", "Explicit matching approval required.")
        result = verify_containment(self.post_containment_graph, self.paths_before, applied)
        self._record("verification_performed",
                     "verified" if result.containment_verified else "incomplete",
                     f"Recalculated paths: {result.paths_before} before, {result.paths_after} after.")
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incomplete", action="store_true",
                        help="Propose only Deployment Token revocation.")
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--missing-telemetry", action="store_true",
                        help="Omit credential-file and token-authentication telemetry.")
    decision = parser.add_mutually_exclusive_group()
    decision.add_argument("--approve", metavar="ANALYST", help="Explicit simulated analyst approval.")
    decision.add_argument("--deny", metavar="ANALYST", help="Explicit simulated analyst denial.")
    args = parser.parse_args()
    graph = AttackGraph()
    graph.load_environment(Path(__file__).resolve().parents[1] / "data" / "environment.json")
    selected = ([a for a in candidate_actions(graph) if a.id == "revoke-deploy"]
                if args.incomplete else None)
    events = load_events(args.events)
    if args.missing_telemetry:
        events = missing_telemetry_events(events)
    workflow = ContainmentWorkflow(graph, selected, events=events)
    print("CHAINBREAK - CONTROLLED CONTAINMENT WORKFLOW")
    print("Simulation only; no external actions or APIs.")
    print("\nINITIAL INCIDENT ANALYSIS")
    print_incident_analysis(graph, workflow.incident_analysis)
    print("\nRECOMMENDATION")
    proposal = workflow.recommendation
    if proposal:
        print("Selected containment: " + (" + ".join(a.name for a in proposal.actions) or "No action needed"))
        print(f"Operational cost: {proposal.operational_cost}")
        print(f"Recommendation ID: {proposal.id}")
        print("Human approval required: yes")
        if args.incomplete:
            print("Deliberate incomplete-containment proposal (analyst selected).")
    else:
        print("No complete containment recommendation available.")
    print("\nAPPROVAL")
    if proposal and (args.approve is not None or args.deny is not None):
        workflow.record_approval(args.approve is not None,
                                 args.approve if args.approve is not None else args.deny,
                                 "Explicit CLI simulation decision.")
        print(f"Simulated analyst: {workflow.approval.approver}; {workflow.approval.status}")
    else:
        print("No approval granted. Use --approve ANALYST for simulated approval.")
    result = workflow.execute()
    print("\nCONTROLLED ACTION")
    print("Actions applied (simulation only): " + (", ".join(result.actions_applied) or "none"))
    print("\nVERIFICATION")
    print(f"Paths before: {result.paths_before}")
    print(f"Paths after: {result.paths_after}")
    print("CONTAINMENT VERIFIED" if result.containment_verified else "CONTAINMENT INCOMPLETE")
    for path in result.remaining_paths:
        print("Remaining: " + graph.describe_path(path))
    print("\nAUDIT TRAIL")
    for index, event in enumerate(workflow.audit_events, 1):
        print(f"{index}. {event.timestamp} | {event.event_type} | {event.status} | "
              f"recommendation={event.recommendation_id or '-'} | "
              f"actions={','.join(event.action_ids) or '-'} | {event.details}")


if __name__ == "__main__":
    main()
