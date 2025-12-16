"""Report generation for threat modeling outputs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from jinja2 import Environment, FileSystemLoader, select_autoescape

from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.models.threat import Threat
from shellthreatmodel.utils.analysis_io import serialize_analysis

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html", "xml")),
    trim_blocks=True,
    lstrip_blocks=True,
)


class ReportFormat(str):
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"


def _trust_zone_lookup(architecture: ArchitectureModel) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for boundary in architecture.trust_boundaries:
        for component in boundary.components:
            lookup[component] = boundary.name
    return lookup


def _architecture_findings(architecture: ArchitectureModel) -> list[dict[str, Any]]:
    """Best-effort architecture flaw/finding extraction.

    These findings are heuristic (not a vulnerability scanner). They aim to highlight common
    weak spots in diagrams: unclear trust boundaries, risky protocols on sensitive flows,
    unknown endpoints, and missing metadata.
    """

    findings: list[dict[str, Any]] = []
    zones = _trust_zone_lookup(architecture)
    component_names = {c.name for c in architecture.components}

    if not architecture.trust_boundaries:
        findings.append(
            {
                "severity": "Medium",
                "area": "Trust Boundaries",
                "summary": "No trust boundaries defined",
                "details": "Without trust zones, it's harder to reason about privilege boundaries and cross-zone controls.",
                "items": [],
            }
        )

    unspecified_types = [c.name for c in architecture.components if (c.type or "").lower() in {"", "unspecified"}]
    if unspecified_types:
        findings.append(
            {
                "severity": "Low",
                "area": "Components",
                "summary": "Some components have unspecified type",
                "details": "Component type is used to infer threats. Add types like 'api', 'database', 'queue', 'auth', 'gateway'.",
                "items": unspecified_types,
            }
        )

    unzoned_components = [c.name for c in architecture.components if c.name not in zones]
    if unzoned_components:
        findings.append(
            {
                "severity": "Medium",
                "area": "Trust Boundaries",
                "summary": "Some components are not assigned to a trust boundary",
                "details": "Assign every component to a trust zone to make cross-boundary flows explicit.",
                "items": unzoned_components,
            }
        )

    empty_boundaries = [b.name for b in architecture.trust_boundaries if not b.components]
    if empty_boundaries:
        findings.append(
            {
                "severity": "Info",
                "area": "Trust Boundaries",
                "summary": "Some trust boundaries contain no components",
                "details": "Consider removing them or assigning components so the diagram remains meaningful.",
                "items": empty_boundaries,
            }
        )

    insecure_protocols = {"http", "tcp", "ftp", "telnet", "smtp"}
    missing_protocol_flows: list[str] = []
    insecure_sensitive_flows: list[str] = []
    unknown_endpoint_flows: list[str] = []
    cross_zone_flows: list[str] = []

    for flow in architecture.data_flows:
        flow_id = f"{flow.source} -> {flow.destination}"
        if flow.source not in component_names or flow.destination not in component_names:
            unknown_endpoint_flows.append(flow_id)

        protocol = (flow.protocol or "").lower().strip()
        if not protocol:
            missing_protocol_flows.append(flow_id)
        elif flow.sensitive and protocol in insecure_protocols:
            insecure_sensitive_flows.append(f"{flow_id} ({protocol})")

        src_zone = zones.get(flow.source)
        dst_zone = zones.get(flow.destination)
        if src_zone and dst_zone and src_zone != dst_zone:
            cross_zone_flows.append(f"{flow_id} ({src_zone} → {dst_zone})")

    if unknown_endpoint_flows:
        findings.append(
            {
                "severity": "High",
                "area": "Data Flows",
                "summary": "Some data flows reference unknown components",
                "details": "Flows should only connect defined components. Unknown endpoints often indicate missing diagram elements.",
                "items": unknown_endpoint_flows,
            }
        )

    if missing_protocol_flows:
        findings.append(
            {
                "severity": "Medium",
                "area": "Data Flows",
                "summary": "Some data flows have no protocol specified",
                "details": "Protocol is used to infer transport protections (e.g., HTTPS vs HTTP). Add protocol for every flow.",
                "items": missing_protocol_flows,
            }
        )

    if insecure_sensitive_flows:
        findings.append(
            {
                "severity": "High",
                "area": "Data Flows",
                "summary": "Sensitive data sent over cleartext/weak transport",
                "details": "Sensitive flows should use TLS-protected protocols (e.g., HTTPS, WSS, TLS).",
                "items": insecure_sensitive_flows,
            }
        )

    if cross_zone_flows:
        findings.append(
            {
                "severity": "Info",
                "area": "Data Flows",
                "summary": "Cross-trust-boundary traffic detected",
                "details": "Cross-zone traffic should have explicit authentication/authorization and network policy enforcement.",
                "items": cross_zone_flows,
            }
        )

    return findings


def render_report(
    architecture: ArchitectureModel,
    threats: Sequence[Threat],
    format: str,
    *,
    title: str,
    output_path: Path,
) -> Path:
    """Render the report in the requested format."""

    format_key = format.lower()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if format_key == ReportFormat.JSON:
        output_path.write_text(serialize_analysis(title, architecture, threats), encoding="utf-8")
        return output_path

    template_name = {
        ReportFormat.MARKDOWN: "report.md.j2",
        "md": "report.md.j2",
        ReportFormat.HTML: "report.html.j2",
    }.get(format_key)
    if not template_name:
        raise ValueError(f"Unsupported report format: {format}")

    template = _env.get_template(template_name)
    findings = _architecture_findings(architecture)
    rendered = template.render(
        title=title,
        architecture=architecture,
        threats=list(threats),
        findings=findings,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    output_path.write_text(rendered, encoding="utf-8")
    return output_path
