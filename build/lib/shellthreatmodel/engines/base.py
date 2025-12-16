"""Threat generation engines interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from shellthreatmodel.models.architecture import ArchitectureModel, Component
from shellthreatmodel.models.threat import Threat


class ThreatEngine(ABC):
    """Common interface all threat engines must implement."""

    name: str

    @abstractmethod
    def generate(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Produce STRIDE/DREAD threats for the given architecture."""

    def _trust_zone_lookup(self, architecture: ArchitectureModel) -> dict[str, str]:
        """Build a mapping of component names to their trust zone names."""
        lookup: dict[str, str] = {}
        for boundary in architecture.trust_boundaries:
            for component_name in boundary.components:
                lookup[component_name] = boundary.name
        return lookup


class ThreatEngineError(RuntimeError):
    """Raised when the engine fails to generate threats."""


# Shared utility functions for threat analysis

def is_sensitive_zone(name: str) -> bool:
    """Determine if a trust zone name indicates a sensitive/secure zone."""
    lowered = name.lower()
    return any(keyword in lowered for keyword in (
        "pci", "secure", "internal", "trusted", "prod", "production",
        "private", "confidential", "restricted", "critical"
    ))


def is_external_zone(name: str) -> bool:
    """Determine if a trust zone name indicates an external/public zone."""
    lowered = name.lower()
    return any(keyword in lowered for keyword in (
        "internet", "public", "external", "dmz", "untrusted", "guest"
    ))


def is_sensitive_component(component: Component) -> bool:
    """Determine if a component handles sensitive data or operations."""
    lowered_name = component.name.lower()
    lowered_type = component.type.lower()
    
    # Sensitive keywords in name
    sensitive_keywords = (
        "card", "vault", "token", "secret", "pii", "auth", "payment",
        "credential", "password", "ssn", "health", "medical", "financial",
        "personal", "sensitive", "confidential", "private"
    )
    
    # Sensitive component types
    sensitive_types = {
        "database", "datastore", "queue", "storage", "vault",
        "kms", "hsm", "auth", "idp", "sso"
    }
    
    return (
        any(keyword in lowered_name for keyword in sensitive_keywords) or
        lowered_type in sensitive_types
    )


def is_public_facing(component: Component, trust_lookup: dict[str, str]) -> bool:
    """Determine if a component is public-facing based on name, type, or zone."""
    lowered_name = component.name.lower()
    lowered_type = component.type.lower()
    zone = trust_lookup.get(component.name, "")
    
    # Public indicators
    public_keywords = ("public", "external", "internet", "exposed", "frontend")
    public_types = {"api", "web", "frontend", "load-balancer", "cdn"}
    
    return (
        any(keyword in lowered_name for keyword in public_keywords) or
        lowered_type in public_types or
        (zone and is_external_zone(zone))
    )


def is_privileged_component(component: Component) -> bool:
    """Determine if a component requires elevated privileges."""
    lowered_name = component.name.lower()
    lowered_type = component.type.lower()
    
    privileged_keywords = ("admin", "privileged", "root", "sudo", "superuser", "system")
    privileged_types = {"admin", "portal", "dashboard", "management"}
    
    return (
        any(keyword in lowered_name for keyword in privileged_keywords) or
        lowered_type in privileged_types
    )


def is_cloud_component(component: Component) -> bool:
    """Determine if a component is a cloud service."""
    lowered_name = component.name.lower()
    lowered_type = component.type.lower()
    
    cloud_keywords = (
        "aws", "azure", "gcp", "cloud", "lambda", "s3", "ec2", "rds",
        "dynamodb", "blob", "cosmos", "bigquery", "cloudrun", "fargate",
        "ecs", "aks", "gke", "eks"
    )
    
    cloud_types = {"lambda", "function", "serverless", "faas", "s3", "blob", "bucket"}
    
    return (
        any(keyword in lowered_name for keyword in cloud_keywords) or
        lowered_type in cloud_types
    )


def calculate_risk_score(
    damage: int,
    reproducibility: int,
    exploitability: int,
    affected_users: int,
    discoverability: int
) -> float:
    """Calculate a normalized risk score from DREAD components."""
    total = damage + reproducibility + exploitability + affected_users + discoverability
    return total / 50.0  # Normalize to 0-1 scale (max score is 50)


def get_severity_from_dread(average_dread: float) -> str:
    """Convert DREAD average to severity level."""
    if average_dread >= 8.0:
        return "critical"
    elif average_dread >= 7.0:
        return "high"
    elif average_dread >= 5.0:
        return "medium"
    elif average_dread >= 3.0:
        return "low"
    else:
        return "informational"

