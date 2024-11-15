"""Deterministic STRIDE/DREAD rules engine."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from shellthreatmodel.models.architecture import ArchitectureModel, Component, DataFlow
from shellthreatmodel.models.threat import DreadScore, StrideCategory, Threat
from shellthreatmodel.engines.base import ThreatEngine


class RulesThreatEngine(ThreatEngine):
    """Rule-based STRIDE/DREAD threat generator."""

    name = "rules"

    def __init__(self, base_score: int = 6) -> None:
        self.base_score = base_score

    def generate(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        component_threats = list(self._component_threats(architecture))
        flow_threats = list(self._flow_threats(architecture))
        return component_threats + flow_threats

    def _component_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        for component in architecture.components:
            comp_type = component.type.lower()
            if comp_type in {"database", "datastore", "storage"}:
                yield self._threat(
                    component,
                    "Tampering with stored data",
                    StrideCategory.TAMPERING,
                    "Ensure integrity controls (signatures, versioning) and access restrictions on data stores.",
                    sensitivity_boost=True,
                )
                yield self._threat(
                    component,
                    "Sensitive data disclosure",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Encrypt data at rest and enforce least-privilege access policies.",
                    sensitivity_boost=True,
                )
            if "log" not in comp_type and comp_type in {"api", "service", "application", "web"}:
                yield self._threat(
                    component,
                    "Lack of repudiation evidence",
                    StrideCategory.REPUDIATION,
                    "Introduce tamper-proof logging with correlation IDs and retention policies.",
                )
            if comp_type in {"admin", "portal"} or "admin" in component.name.lower():
                yield self._threat(
                    component,
                    "Privilege escalation via administrative interface",
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Apply role-based access control, MFA, and activity monitoring for administrative consoles.",
                    high_severity=True,
                )

    def _flow_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        trust_lookup = self._trust_zone_lookup(architecture)
        for flow in architecture.data_flows:
            if flow.protocol and flow.protocol.lower() in {"http", "tcp"} and flow.sensitive:
                yield self._flow_threat(
                    flow,
                    "Sensitive data transmitted without transport protection",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Enforce TLS 1.2+ and certificate pinning for sensitive flows.",
                    sensitivity_boost=True,
                )
            if self._crosses_boundary(flow, trust_lookup):
                yield self._flow_threat(
                    flow,
                    "Unauthenticated cross-boundary communication",
                    StrideCategory.SPOOFING,
                    "Add mutual authentication and allow-lists for cross-boundary traffic.",
                )
            if flow.description and "health" not in flow.description.lower() and any(keyword in flow.description.lower() for keyword in ["login", "auth", "token"]):
                yield self._flow_threat(
                    flow,
                    "Credential replay or brute-force against authentication flow",
                    StrideCategory.SPOOFING,
                    "Add rate limiting, anomaly detection, and MFA on authentication endpoints.",
                    high_severity=True,
                )
            if flow.description and any(keyword in flow.description.lower() for keyword in ["batch", "sync", "cron"]):
                yield self._flow_threat(
                    flow,
                    "Resource exhaustion through scheduled operations",
                    StrideCategory.DENIAL_OF_SERVICE,
                    "Add capacity planning, circuit breakers, and backpressure controls for scheduled jobs.",
                )

    def _trust_zone_lookup(self, architecture: ArchitectureModel) -> dict[str, str]:
        lookup: dict[str, str] = {}
        for boundary in architecture.trust_boundaries:
            for component_name in boundary.components:
                lookup[component_name] = boundary.name
        return lookup

    def _crosses_boundary(self, flow: DataFlow, trust_lookup: dict[str, str]) -> bool:
        return trust_lookup.get(flow.source) != trust_lookup.get(flow.destination)

    def _threat(
        self,
        component: Component,
        description: str,
        category: StrideCategory,
        mitigation: str,
        *,
        sensitivity_boost: bool = False,
        high_severity: bool = False,
    ) -> Threat:
        dread = self._score(component.name, category, sensitivity_boost=sensitivity_boost, high_severity=high_severity)
        return Threat(
            component=component.name,
            threat=description,
            stride_category=category,
            dread=dread,
            mitigation=mitigation,
        )

    def _flow_threat(
        self,
        flow: DataFlow,
        description: str,
        category: StrideCategory,
        mitigation: str,
        *,
        sensitivity_boost: bool = False,
        high_severity: bool = False,
    ) -> Threat:
        dread = self._score(
            f"{flow.source}->{flow.destination}", category, sensitivity_boost=sensitivity_boost, high_severity=high_severity
        )
        return Threat(
            component=f"{flow.source}->{flow.destination}",
            threat=description,
            stride_category=category,
            dread=dread,
            mitigation=mitigation,
        )

    def _score(
        self,
        context: str,
        category: StrideCategory,
        *,
        sensitivity_boost: bool = False,
        high_severity: bool = False,
    ) -> DreadScore:
        base = self.base_score
        if sensitivity_boost:
            base = max(base, 7)
        if high_severity:
            base = max(base, 8)
        damage = min(10, base + (2 if high_severity else 0))
        reproducibility = min(10, base + (1 if category in {StrideCategory.SPOOFING, StrideCategory.ELEVATION_OF_PRIVILEGE} else 0))
        exploitability = min(10, base + (1 if sensitivity_boost or high_severity else 0))
        affected_users = min(10, base + (1 if "public" in context.lower() else 0))
        discoverability = min(10, base)
        return DreadScore(
            damage=damage,
            reproducibility=reproducibility,
            exploitability=exploitability,
            affected_users=affected_users,
            discoverability=discoverability,
        )
