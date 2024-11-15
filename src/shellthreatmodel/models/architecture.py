"""Data models for parsed architecture artifacts."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class Component(BaseModel):
    """System component extracted from architecture diagrams."""

    name: str
    type: str = Field(default="unspecified")
    description: Optional[str] = None
    metadata: dict[str, str] = Field(default_factory=dict)


class DataFlow(BaseModel):
    """Represents data movement between two components."""

    source: str
    destination: str
    protocol: Optional[str] = None
    description: Optional[str] = None
    sensitive: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)


class TrustBoundary(BaseModel):
    """Defines trust zones or boundaries in the architecture."""

    name: str
    description: Optional[str] = None
    components: List[str] = Field(default_factory=list)


class ArchitectureModel(BaseModel):
    """Unified model derived from PlantUML, JSON, or YAML inputs."""

    title: str
    components: List[Component] = Field(default_factory=list)
    data_flows: List[DataFlow] = Field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    def component_map(self) -> dict[str, Component]:
        """Return components keyed by name for quick lookup."""

        return {component.name: component for component in self.components}
