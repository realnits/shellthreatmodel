"""Parser for PlantUML component/sequence deployment diagrams."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional

from shellthreatmodel.models.architecture import ArchitectureModel, Component, DataFlow, TrustBoundary
from shellthreatmodel.parsers.base import ArchitectureParser, ParserError

try:  # pragma: no cover - optional dependency
    from plantuml_parser import PlantUMLParser  # type: ignore
except ImportError:  # pragma: no cover - fallback for environments without the dependency
    PlantUMLParser = None  # type: ignore


_COMPONENT_RE = re.compile(r"(?P<type>node|component|database|queue|cloud|artifact)\s+\"(?P<name>[^\"]+)\"", re.IGNORECASE)
_BOUNDARY_RE = re.compile(r"package\s+\"(?P<name>[^\"]+)\"\s+\{", re.IGNORECASE)
_FLOW_RE = re.compile(
    r"(?P<src>[A-Za-z0-9_]+)\s*(-{1,2}>|\.{1,2}>|<-{1,2}|<\.{1,2})\s*(?P<dst>[A-Za-z0-9_]+)\s*(?:[:]\s*(?P<label>.+))?"
)
_ALIAS_RE = re.compile(r"as\s+(?P<alias>[A-Za-z0-9_]+)")


class PlantUMLArchitectureParser(ArchitectureParser):
    """Parse PlantUML architecture diagrams into the intermediate model."""

    extensions = {".puml", ".plantuml", ".uml", ".txt"}

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions

    def parse(self, path: Path) -> ArchitectureModel:
        if not path.exists():
            raise ParserError(f"File not found: {path}")
        text = path.read_text(encoding="utf-8")
        if PlantUMLParser:  # pragma: no cover - heavy dependency
            return self._parse_with_library(text, title=path.stem)
        return self._parse_with_regex(text, title=path.stem)

    def _parse_with_library(self, text: str, title: str) -> ArchitectureModel:
        parser = PlantUMLParser(text)
        model = parser.parse()
        components = [
            Component(name=node.name, type=node.type or "component", description=node.label)
            for node in model.nodes
        ]
        flows = [
            DataFlow(
                source=link.source.name,
                destination=link.target.name,
                description=link.label,
                metadata={"link_type": link.type},
            )
            for link in model.links
        ]
        boundaries = [
            TrustBoundary(
                name=package.name,
                description=package.label,
                components=[node.name for node in package.children],
            )
            for package in model.packages
        ]
        return ArchitectureModel(title=title, components=components, data_flows=flows, trust_boundaries=boundaries)

    def _parse_with_regex(self, text: str, title: str) -> ArchitectureModel:
        components: list[Component] = []
        flows: list[DataFlow] = []
        boundaries: list[TrustBoundary] = []
        aliases: dict[str, str] = {}
        boundary_stack: list[TrustBoundary] = []

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("'"):
                continue

            boundary_match = _BOUNDARY_RE.search(stripped)
            if boundary_match:
                boundary = TrustBoundary(name=boundary_match.group("name"), components=[])
                boundary_stack.append(boundary)
                boundaries.append(boundary)
                continue
            if stripped == "}":
                if boundary_stack:
                    boundary_stack.pop()
                continue

            comp_match = _COMPONENT_RE.search(stripped)
            if comp_match:
                alias = _extract_alias(stripped)
                name = comp_match.group("name")
                comp_type = comp_match.group("type").lower()
                components.append(Component(name=name, type=comp_type, metadata={"alias": alias} if alias else {}))
                if alias:
                    aliases[alias] = name
                if boundary_stack:
                    boundary_stack[-1].components.append(name)
                continue

            flow_match = _FLOW_RE.search(stripped)
            if flow_match:
                source = aliases.get(flow_match.group("src"), flow_match.group("src"))
                destination = aliases.get(flow_match.group("dst"), flow_match.group("dst"))
                label = flow_match.group("label")
                flows.append(
                    DataFlow(
                        source=source,
                        destination=destination,
                        description=label,
                        metadata={"raw": stripped},
                        sensitive=_is_sensitive(label),
                    )
                )

        return ArchitectureModel(title=title, components=components, data_flows=flows, trust_boundaries=boundaries)


def _extract_alias(line: str) -> Optional[str]:
    match = _ALIAS_RE.search(line)
    if match:
        return match.group("alias")
    return None


def _is_sensitive(label: Optional[str]) -> bool:
    if not label:
        return False
    keywords = ("pii", "card", "ssn", "secret", "token", "password", "key")
    return any(keyword in label.lower() for keyword in keywords)
