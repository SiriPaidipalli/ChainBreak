"""ChainBreak's simulation-only dashboard. Launch with streamlit run app.py."""

from pathlib import Path
from datetime import datetime

import graphviz
import streamlit as st

from src.containment import candidate_actions, evaluate_actions
from src.graph import AttackGraph
from src.workflow import ContainmentWorkflow

ROOT = Path(__file__).resolve().parent


def new_demo():
    graph = AttackGraph()
    graph.load_environment(ROOT / "data" / "environment.json")
    workflow = ContainmentWorkflow(graph)
    return {"graph": graph, "workflow": workflow, "result": None,
            "recommended": workflow.recommendation}


def reset_demo():
    st.session_state.demo = new_demo()


def execute_demo(partial=False):
    demo = st.session_state.demo
    if demo["result"] is not None:
        return
    workflow = demo["workflow"]
    if partial:
        actions = [a for a in candidate_actions(demo["graph"]) if a.id == "revoke-deploy"]
        workflow = ContainmentWorkflow(demo["graph"], selected_actions=actions)
    workflow.record_approval(True, "SOC-Analyst", "Explicit dashboard approval; simulation only.")
    demo["result"] = workflow.execute()
    demo["workflow"] = workflow


def graph_view(original, current):
    """Presentation only: reachability and removal state come from the backend."""
    paths = current.find_attack_paths(current.compromised_entity, current.protected_asset)
    active_edges = {pair for path in paths for pair in zip(path, path[1:])}
    dot = graphviz.Digraph()
    dot.attr(rankdir="LR", bgcolor="transparent", pad="0.3", nodesep="0.65", ranksep="0.75", ordering="out")
    dot.attr("node", shape="box", style="rounded,filled", fontname="Arial", fontsize="13", margin="0.18,0.16")
    dot.attr("edge", fontname="Arial", fontsize="9", arrowsize="0.7")
    for entity in original.entities.values():
        removed = entity.id not in current.entities
        color, fill, role = "#64748b", "#f1f5f9", "Infrastructure"
        if entity.id == original.compromised_entity:
            color, fill, role = "#dc2626", "#fee2e2", "Compromised identity"
        elif entity.id == original.protected_asset:
            color, fill, role = "#047857", "#d1fae5", "Protected asset"
        elif entity.type == "credential":
            color, fill, role = "#b45309", "#fef3c7", "Credential"
        if removed:
            color, fill, role = "#94a3b8", "#e2e8f0", "CONTAINED · simulated"
        dot.node(entity.id, label=f"{entity.name}\n{role}", color=color, fillcolor=fill,
                 fontcolor="#334155", style="dashed,filled" if removed else "rounded,filled",
                 shape=("cylinder" if entity.id == original.protected_asset else
                        "octagon" if entity.id == original.compromised_entity else
                        "component" if entity.type == "credential" else "box"),
                 penwidth="2")
    live_edges = {(r.source, r.target, r.type) for r in current.relationships}
    for relation in original.relationships:
        live = (relation.source, relation.target, relation.type) in live_edges
        active = live and (relation.source, relation.target) in active_edges
        dot.edge(relation.source, relation.target,
                 label=relation.type.replace("_", " ") if live else "blocked",
                 color="#dc2626" if active else "#94a3b8",
                 fontcolor="#64748b", penwidth="3" if active else "1",
                 style="solid" if live else "dashed")
    return dot


def main():
    st.set_page_config(page_title="ChainBreak | Containment", layout="wide")
    st.markdown("""<style>
        .block-container {max-width: 1480px; padding-top: 2rem; padding-bottom: 2rem;}
        h1 {letter-spacing: -0.04em;} h2 {letter-spacing: -0.02em;}
        [data-testid="stMetric"] {background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px;}
        [data-testid="stMetricValue"] {font-variant-numeric: tabular-nums;}
        [data-testid="stExpander"] {border-color: #e2e8f0;}
        </style>""", unsafe_allow_html=True)
    if "demo" not in st.session_state:
        reset_demo()
    demo = st.session_state.demo
    graph, workflow, result = demo["graph"], demo["workflow"], demo["result"]
    analysis = workflow.incident_analysis
    header, reset = st.columns([5, 1])
    with header:
        st.title("ChainBreak")
        st.write("Attack-Path-Aware Containment for Security Incidents")
        st.caption("Synthetic enterprise environment · Simulation only")
    with reset:
        st.button("Reset Demo", key="reset", on_click=reset_demo, width="stretch")
    st.write(f"**Compromised identity:** {graph.entities[graph.compromised_entity].name}"
             f"  ·  **Protected asset:** {graph.entities[graph.protected_asset].name}")
    metrics = st.columns(5)
    metrics[0].metric("Viable paths · current", result.paths_after if result else workflow.paths_before)
    metrics[1].metric("Risk · initial", f"{analysis.risk_score}/100")
    metrics[2].metric("Severity · initial", analysis.severity.upper())
    metrics[3].metric("Evidence confidence", f"{analysis.confidence:g}/100")
    metrics[4].metric("Priority · initial", analysis.priority)
    st.caption("Risk and evidence describe the initial incident. Confidence measures evidence coverage, not probability of compromise.")

    st.subheader("Attack graph")
    if result:
        if result.containment_verified:
            st.success("**CONTAINMENT VERIFIED** · Independently verified after simulated action")
        else:
            st.error("**CONTAINMENT INCOMPLETE** · A viable attacker route remains after simulated action")
        before, after = st.columns(2)
        before.metric("Paths before", result.paths_before)
        after.metric("Paths after · verified", result.paths_after)
        st.caption("Applied in simulation: " + " + ".join(a.name for a in workflow.recommendation.actions))
    else:
        st.info("Analysis only. No actions applied. Explicit analyst approval is required below.")
    current = workflow.post_containment_graph if result else graph
    with st.container(border=True):
        st.graphviz_chart(graph_view(graph, current), width="stretch")
    st.caption("Red routes: reachable attack paths · Octagon: compromised identity · Amber: credentials · Green cylinder: protected asset · "
               "Gray dashed nodes/edges: contained references, absent from the post-action graph")
    if result:
        for path in result.remaining_paths:
            st.warning("**Surviving route**  \n" + graph.describe_path(path))
        with st.expander("Compare original attack graph"):
            st.graphviz_chart(graph_view(graph, graph), width="stretch")

    left, right = st.columns([3, 2], gap="large")
    with left:
        st.subheader("Attack-path evidence")
        st.caption("Initial reconstructed paths and their supporting observations")
        events = {event.event_id: event for event in analysis.evidence}
        for index, path in enumerate(analysis.paths, 1):
            with st.container(border=True):
                st.markdown(f"**Attack Path {index}** · {path.coverage:.0%} evidence coverage")
                st.write(graph.describe_path(path.path))
                st.caption(f"{path.supported_transitions}/{path.total_transitions} transitions supported")
                with st.expander(f"Supporting evidence · Path {index}"):
                    ids = sorted({i for values in path.transition_evidence.values() for i in values})
                    for event_id in ids:
                        st.write(f"**{event_id}** — {events[event_id].description}")
                    for (source, target), values in path.transition_evidence.items():
                        if not values:
                            st.caption(f"No telemetry: {graph.entities[source].name} → {graph.entities[target].name}")
    with right:
        st.subheader("Risk reasoning")
        for factor in analysis.risk_factors:
            st.write(f"**+{factor.points}** · {factor.details}")
        if analysis.telemetry_incomplete:
            st.warning("Telemetry is incomplete; evidence confidence is reduced.")
        with st.expander("Observed evidence"):
            for event in analysis.evidence:
                st.write(f"**{event.event_id} · {event.severity.upper()}** — {event.description}")
                st.caption(f"{event.timestamp} · {event.source}")
        with st.expander("MITRE ATT&CK context"):
            st.caption("Rule-based context, not proof of intent.")
            for mapping in analysis.attack_mappings:
                st.write(f"**{mapping.technique_id} — {mapping.technique_name}**")
                st.caption(f"{mapping.event_id}: {mapping.description}")

    st.subheader("Containment analysis")
    st.caption("Candidate impacts against the original incident · costs are synthetic disruption units")
    candidates = candidate_actions(graph)
    rows = []
    for evaluation in evaluate_actions(graph, candidates):
        action = evaluation.actions[0]
        rows.append({"Action": action.name, "Target": graph.entities[action.target_entity].name,
                     "Operational cost": evaluation.operational_cost, "Paths broken": evaluation.paths_broken,
                     "Paths remaining": evaluation.paths_after,
                     "Containment": "COMPLETE" if evaluation.containment_complete else "INCOMPLETE"})
    st.dataframe(rows, hide_index=True, width="stretch",
                 column_order=["Action", "Operational cost", "Paths broken", "Paths remaining", "Containment"],
                 column_config={"Action": st.column_config.TextColumn(width="large"),
                                "Operational cost": st.column_config.NumberColumn("Cost", format="%d"),
                                "Containment": st.column_config.TextColumn("Predicted status")})
    # Preserve the original optimizer's proposal when demonstrating a partial action.
    proposal = demo["recommended"]
    with st.container(border=True):
        st.subheader("Recommended containment")
        if proposal:
            for action in proposal.actions:
                st.markdown(f"### {action.name}")
            if not proposal.actions:
                st.write("No action needed")
            cost, predicted = st.columns(2)
            cost.metric("Operational cost", proposal.operational_cost)
            predicted.metric("Predicted remaining paths", proposal.predicted_paths_after)
            st.write("Lowest-impact complete containment based on configured operational disruption costs.")
            st.caption("Prediction for the original incident. The graph above shows independently verified results after action.")
            comparison = [{"Containment option": "Recommended containment", "Cost": proposal.operational_cost}]
            comparison.extend({"Containment option": action.name, "Cost": action.operational_cost}
                              for action in candidates
                              if action.id in {"disable-alice", "isolate-laptop", "isolate-dev"})
            st.markdown("**Operational impact comparison**")
            st.dataframe(comparison, hide_index=True, width="stretch")
            st.markdown("**Human approval required**")
            st.caption("Approval records SOC-Analyst and applies actions in simulation only.")
        else:
            st.warning("No complete containment recommendation available.")
        approve_col, partial_col = st.columns([3, 2])
        approve_col.button("Approve Recommended Containment", key="approve", type="primary",
                           disabled=result is not None or proposal is None,
                           on_click=execute_demo, width="stretch")
        partial_col.button("Test Partial Containment", key="partial", disabled=result is not None,
                           on_click=execute_demo, args=(True,), width="stretch")
        st.caption("Test Partial Containment explicitly approves only Deployment Token revocation as SOC-Analyst. "
                   "Reset Demo to compare another scenario.")
    st.subheader("Audit trail")
    st.dataframe([{"Event": e.event_type.replace("_", " ").capitalize(),
                   "Status": e.status.capitalize(), "Details": e.details,
                   "Timestamp (UTC)": datetime.fromisoformat(e.timestamp).strftime("%Y-%m-%d %H:%M:%S")}
                  for e in workflow.audit_events],
                 hide_index=True, width="stretch")
    st.caption("Simulation only. No real accounts, tokens, hosts, or services are changed. No external response APIs or shell commands.")


if __name__ == "__main__":
    main()
