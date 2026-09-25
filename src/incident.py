"""Deterministic evidence and risk context; no response decisions or integrations."""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from src.graph import AttackGraph

DEFAULT_EVENTS = Path(__file__).resolve().parents[1] / "data" / "events.json"

# A matching pair alone is insufficient: the behavior must support the edge type.
TRANSITION_RULES = {
    "unusual_login_success": "uses",
    "ssh_login_success": "can_access",
    "credential_file_read": "stores_credential",
    "token_authentication": "authenticates_to",
    "database_access_attempt": "can_access",
}
# Context labels, not proof of malicious intent. References are in README.md.
ATTACK_RULES = {
    "unusual_login_success": ("T1078", "Valid Accounts"),
    "suspicious_powershell": ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "credential_file_read": ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    "ssh_login_success": ("T1021.004", "Remote Services: SSH"),
}


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: str
    source: str
    event_type: str
    actor: str
    target: str
    severity: str
    description: str


@dataclass
class PathEvidence:
    path: list[str]
    transition_evidence: dict[tuple[str, str], tuple[str, ...]]
    supported_transitions: int
    total_transitions: int
    coverage: float


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    technique_name: str
    event_id: str
    description: str


@dataclass(frozen=True)
class RiskFactor:
    name: str
    points: int
    details: str


@dataclass
class IncidentAnalysis:
    evidence: list[SecurityEvent]
    supported_entities: list[str]
    supported_relationships: dict[tuple[str, str], tuple[str, ...]]
    paths: list[PathEvidence]
    evidence_coverage: float
    telemetry_incomplete: bool
    risk_score: int
    severity: str
    confidence: float
    confidence_level: str
    priority: str
    risk_factors: list[RiskFactor]
    attack_mappings: list[AttackMapping]


def load_events(file_path=DEFAULT_EVENTS) -> list[SecurityEvent]:
    """A missing telemetry file is treated as no observations, not no risk."""
    try:
        with open(file_path, encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        return []
    return [SecurityEvent(**item) for item in data["events"]]


def missing_telemetry_events(events: Iterable[SecurityEvent]) -> list[SecurityEvent]:
    """Demo gap: credential-file and service-authentication logs are unavailable."""
    return [event for event in events if event.event_type not in
            {"credential_file_read", "token_authentication"}]


def analyze_incident(graph: AttackGraph, events: Iterable[SecurityEvent]) -> IncidentAnalysis:
    paths = graph.find_attack_paths(graph.compromised_entity, graph.protected_asset)
    path_entities = {entity for path in paths for entity in path}
    # Retain endpoint observations even when no full route is currently viable.
    relevant_entities = path_entities | {graph.compromised_entity, graph.protected_asset}
    transitions = {pair for path in paths for pair in zip(path, path[1:])}
    edges = {(r.source, r.target, r.type) for r in graph.relationships}
    evidence = []
    entity_support = set()
    support = {}
    mappings = []
    seen = set()
    for event in sorted(events, key=lambda event: (event.timestamp, event.event_id)):
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        # Both identifiers must resolve, and both must be in this incident's scope.
        if not all(entity in graph.entities and entity in relevant_entities
                   for entity in (event.actor, event.target)):
            continue
        evidence.append(event)
        entity_support.update((event.actor, event.target))
        pair = (event.actor, event.target)
        matching_edge = (event.actor, event.target, TRANSITION_RULES.get(event.event_type)) in edges
        if matching_edge and pair in transitions:
            support.setdefault(pair, []).append(event.event_id)
        # PowerShell is an entity-local behavior; other labels require a matching edge.
        powershell = (event.event_type == "suspicious_powershell"
                      and graph.entities[event.actor].type == "user"
                      and graph.entities[event.target].type == "host")
        if event.event_type in ATTACK_RULES and (matching_edge or powershell):
            technique_id, name = ATTACK_RULES[event.event_type]
            mappings.append(AttackMapping(technique_id, name, event.event_id, event.description))

    support = {pair: tuple(ids) for pair, ids in support.items()}
    path_evidence = []
    for path in paths:
        pairs = list(zip(path, path[1:]))
        observed = {pair: support.get(pair, ()) for pair in pairs}
        count = sum(bool(ids) for ids in observed.values())
        path_evidence.append(PathEvidence(path, observed, count, len(pairs),
                                          count / len(pairs) if pairs else 0.0))
    coverage = len(support) / len(transitions) if transitions else 0.0
    reachable = bool(paths)
    criticality = graph.entities[graph.protected_asset].criticality
    asset_points = {"critical": 30, "high": 20, "medium": 10, "low": 0}.get(criticality, 0)
    credential_observed = any(
        event.event_type == "credential_file_read"
        and graph.entities[event.target].type == "credential"
        and (event.actor, event.target) in support
        for event in evidence
    )
    factors = [
        RiskFactor("asset_criticality", asset_points if reachable else 0,
                   f"Protected asset criticality: {criticality or 'unspecified'}; reachable: {reachable}."),
        RiskFactor("reachability", 25 if reachable else 0,
                   "Protected asset reachable by graph traversal." if reachable else "No viable route to protected asset."),
        RiskFactor("alternate_paths", 10 if len(paths) >= 2 else 0,
                   f"{len(paths)} viable attack paths; alternate routes complicate containment."),
        RiskFactor("credential_exposure", 15 if credential_observed else 0,
                   "Credential-file access observed." if credential_observed else "No supporting credential-file access telemetry."),
        RiskFactor("evidence_coverage", round(20 * coverage),
                   f"{len(support)}/{len(transitions)} unique path transitions supported by telemetry."),
    ]
    score = min(100, sum(factor.points for factor in factors))
    severity = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    confidence = round(100 * coverage, 1)
    level = "high" if confidence >= 80 else "medium" if confidence >= 50 else "low"
    return IncidentAnalysis(
        evidence, sorted(entity_support), support, path_evidence, coverage,
        not transitions or len(support) < len(transitions), score, severity,
        confidence, level, {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}[severity],
        factors, mappings,
    )


def print_incident_analysis(graph: AttackGraph, analysis: IncidentAnalysis) -> None:
    print(f"Compromised identity: {graph.entities[graph.compromised_entity].name}")
    print(f"Protected asset: {graph.entities[graph.protected_asset].name}")
    print("\nOBSERVED EVIDENCE (synthetic)")
    for event in analysis.evidence:
        print(f"[{event.event_id}] {event.timestamp} | {event.source} | {event.severity}: {event.description}")
    if not analysis.evidence:
        print("No relevant telemetry available.")
    print("\nATTACK PATHS")
    print(f"Viable attack paths: {len(analysis.paths)}")
    for index, path in enumerate(analysis.paths, 1):
        print(f"Path {index}: {graph.describe_path(path.path)}")
        print(f"Evidence coverage: {path.supported_transitions}/{path.total_transitions} ({path.coverage:.0%})")
        for (source, target), event_ids in path.transition_evidence.items():
            print(f"  {graph.entities[source].name} -> {graph.entities[target].name}: "
                  + (", ".join(event_ids) or "NO TELEMETRY"))
    print("\nRISK ASSESSMENT")
    print(f"Risk score: {analysis.risk_score}/100 | Severity: {analysis.severity} | Priority: {analysis.priority}")
    print(f"Confidence: {analysis.confidence}/100 ({analysis.confidence_level})")
    print("Confidence measures transition coverage, not probability of compromise.")
    print("Telemetry/evidence INCOMPLETE." if analysis.telemetry_incomplete
          else "All modeled transitions have telemetry; database access attempts do not prove compromise.")
    print("Risk factors:")
    for factor in analysis.risk_factors:
        print(f"  +{factor.points}: {factor.details}")
    print("\nMITRE ATT&CK (rule-based context, not proof of intent)")
    for mapping in analysis.attack_mappings:
        print(f"{mapping.technique_id} - {mapping.technique_name}")
        print(f"  Evidence: [{mapping.event_id}] {mapping.description}")
    if not analysis.attack_mappings:
        print("No supported technique mappings.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--missing-telemetry", action="store_true")
    args = parser.parse_args()
    graph = AttackGraph()
    graph.load_environment(DEFAULT_EVENTS.parent / "environment.json")
    events = load_events(args.events)
    if args.missing_telemetry:
        events = missing_telemetry_events(events)
    print("CHAINBREAK - INCIDENT ANALYSIS\n\nINCIDENT")
    print_incident_analysis(graph, analyze_incident(graph, events))


if __name__ == "__main__":
    main()
