"""Attack graph generation helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from graphviz import Digraph

from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.models.threat import Threat


def export_attack_graph(architecture: ArchitectureModel, threats: Iterable[Threat], output_path: Path) -> Path:
    """Render a simple attack graph using Graphviz."""

    graph = Digraph("threat_graph", format=output_path.suffix.lstrip("."))
    graph.attr(rankdir="LR", splines="curved", stylesheet="")

    for component in architecture.components:
        graph.node(component.name, label=f"{component.name}\n({component.type})", shape="box")

    for threat in threats:
        threat_node_id = f"threat_{hash(threat.threat) % 10_000_000}"
        graph.node(
            threat_node_id,
            label=f"{threat.stride_category.value}\n{threat.threat}\nRisk: {threat.risk_level()}",
            shape="octagon",
            color=_risk_color(threat.risk_level()),
            fontcolor="#0b0d17",
        )
        if "->" in threat.component:
            src, dst = threat.component.split("->", 1)
            graph.edge(src, threat_node_id, label="threatens")
            graph.edge(threat_node_id, dst, label="impacts")
        else:
            graph.edge(threat.component, threat_node_id, label="threatens")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    graph.render(filename=output_path.stem, directory=str(output_path.parent), cleanup=True)
    return output_path


def _risk_color(risk: str) -> str:
    match risk:
        case "High":
            return "#e53935"
        case "Medium":
            return "#fb8c00"
        case _:
            return "#43a047"
