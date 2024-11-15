"""PASTA (Process for Attack Simulation and Threat Analysis) engine."""

from __future__ import annotations

from typing import Iterable

from shellthreatmodel.engines.base import ThreatEngine
from shellthreatmodel.models.architecture import ArchitectureModel, Component, DataFlow
from shellthreatmodel.models.threat import DreadScore, StrideCategory, Threat


class PASTAThreatEngine(ThreatEngine):
    """Generate threat scenarios aligned with the PASTA methodology."""

    name = "pasta"

    def generate(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        trust_lookup = self._trust_zone_lookup(architecture)
        sensitive_zones = {name for name in trust_lookup.values() if name and _is_sensitive_zone(name)}
        external_zones = {name for name in trust_lookup.values() if name and _is_external_zone(name)}

        threats: list[Threat] = []
        threats.extend(self._step4_surface_analysis(architecture, trust_lookup, external_zones))
        threats.extend(self._step5_weakness_analysis(architecture, trust_lookup, external_zones, sensitive_zones))
        threats.extend(self._step6_attack_modeling(architecture, trust_lookup, sensitive_zones))
        threats.extend(self._step7_risk_analysis(architecture))
        return threats

    def _step4_surface_analysis(
        self,
        architecture: ArchitectureModel,
        trust_lookup: dict[str, str],
        external_zones: set[str],
    ) -> Iterable[Threat]:
        for component in architecture.components:
            zone = trust_lookup.get(component.name, "")
            if zone and zone in external_zones:
                description = (
                    f"Attackers enumerate exposed service '{component.name}' in zone '{zone}' to discover misconfigurations."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Apply attack surface management, hardened configuration baselines, and continuous monitoring.",
                    stage=4,
                    stage_title="Threat Analysis",
                    severity="medium",
                    sensitive=_is_sensitive_component(component),
                )

    def _step5_weakness_analysis(
        self,
        architecture: ArchitectureModel,
        trust_lookup: dict[str, str],
        external_zones: set[str],
        sensitive_zones: set[str],
    ) -> Iterable[Threat]:
        for flow in architecture.data_flows:
            source_zone = trust_lookup.get(flow.source, "")
            destination_zone = trust_lookup.get(flow.destination, "")
            if not source_zone or not destination_zone or source_zone == destination_zone:
                continue

            severity = "medium"
            if source_zone in external_zones and destination_zone in sensitive_zones:
                severity = "high"
            description = (
                f"Attack path from '{flow.source}' ({source_zone or 'unknown zone'}) to '{flow.destination}' ({destination_zone or 'unknown zone'}) "
                "is exploitable if boundary controls fail."
            )
            mitigation = "Enforce mutual authentication, network segmentation, and anomaly detection on boundary crossings."
            if flow.sensitive:
                mitigation = (
                    "Enforce mutual authentication, network segmentation, data sensitivity tagging, and anomaly detection on boundary crossings."
                )
            yield self._threat(
                f"{flow.source}->{flow.destination}",
                description,
                StrideCategory.SPOOFING,
                mitigation,
                stage=5,
                stage_title="Weakness & Vulnerability Analysis",
                severity=severity,
                sensitive=flow.sensitive,
            )

    def _step6_attack_modeling(
        self,
        architecture: ArchitectureModel,
        trust_lookup: dict[str, str],
        sensitive_zones: set[str],
    ) -> Iterable[Threat]:
        for component in architecture.components:
            if component.type.lower() not in {"database", "datastore", "storage", "queue"}:
                continue
            zone = trust_lookup.get(component.name, "")
            sensitive = _is_sensitive_component(component) or zone in sensitive_zones
            description = (
                f"Attack simulation targets data store '{component.name}' to exfiltrate or corrupt critical records."
            )
            yield self._threat(
                component.name,
                description,
                StrideCategory.INFORMATION_DISCLOSURE if sensitive else StrideCategory.TAMPERING,
                "Implement layered data protection: encryption, immutable backups, and just-in-time privileged access.",
                stage=6,
                stage_title="Attack Modeling & Simulation",
                severity="high" if sensitive else "medium",
                sensitive=sensitive,
            )

    def _step7_risk_analysis(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        for flow in architecture.data_flows:
            if not flow.description:
                continue
            if any(keyword in flow.description.lower() for keyword in ("batch", "etl", "job", "sync", "pipeline")):
                description = (
                    f"Operational analytics flow '{flow.description}' could be disrupted causing downstream impact to decisioning."
                )
                yield self._threat(
                    f"{flow.source}->{flow.destination}",
                    description,
                    StrideCategory.DENIAL_OF_SERVICE,
                    "Introduce resiliency patterns: retries, circuit breakers, and resource quotas for analytics workloads.",
                    stage=7,
                    stage_title="Residual Risk & Impact Analysis",
                    severity="medium",
                    sensitive=flow.sensitive,
                )

    def _threat(
        self,
        component: str,
        description: str,
        category: StrideCategory,
        mitigation: str,
        *,
        stage: int,
        stage_title: str,
        severity: str,
        sensitive: bool,
    ) -> Threat:
        dread = self._score(severity=severity, sensitive=sensitive)
        methodology = f"PASTA Step {stage}: {stage_title}"
        return Threat(
            component=component,
            threat=description,
            stride_category=category,
            dread=dread,
            mitigation=mitigation,
            methodology=methodology,
        )

    def _score(self, *, severity: str, sensitive: bool) -> DreadScore:
        base_map = {"low": 4, "medium": 6, "high": 8}
        base = base_map.get(severity, 6)
        if sensitive:
            base = min(9, base + 1)
        damage = min(10, base + (1 if severity == "high" else 0))
        reproducibility = min(10, base)
        exploitability = min(10, base + (1 if severity != "low" else 0))
        affected_users = min(10, base + (1 if severity == "high" else 0))
        discoverability = min(10, base - 1 if base > 5 else base)
        return DreadScore(
            damage=damage,
            reproducibility=reproducibility,
            exploitability=exploitability,
            affected_users=affected_users,
            discoverability=discoverability,
        )

    def _trust_zone_lookup(self, architecture: ArchitectureModel) -> dict[str, str]:
        lookup: dict[str, str] = {}
        for boundary in architecture.trust_boundaries:
            for component_name in boundary.components:
                lookup[component_name] = boundary.name
        return lookup


def _is_sensitive_zone(name: str) -> bool:
    lowered = name.lower()
    return any(keyword in lowered for keyword in ("pci", "secure", "internal", "trusted", "prod"))


def _is_external_zone(name: str) -> bool:
    lowered = name.lower()
    return any(keyword in lowered for keyword in ("internet", "public", "external", "dmz"))


def _is_sensitive_component(component: Component) -> bool:
    lowered_name = component.name.lower()
    lowered_type = component.type.lower()
    return any(keyword in lowered_name for keyword in ("card", "vault", "token", "secret", "pii", "auth")) or lowered_type in {
        "database",
        "datastore",
        "queue",
        "storage",
    }