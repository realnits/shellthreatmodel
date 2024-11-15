"""Utilities for loading architecture files."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.parsers.base import ArchitectureParser, ParserError
from shellthreatmodel.parsers.drawio_parser import DrawioArchitectureParser
from shellthreatmodel.parsers.json_parser import JSONArchitectureParser
from shellthreatmodel.parsers.plantuml_parser import PlantUMLArchitectureParser
from shellthreatmodel.parsers.yaml_parser import YAMLArchitectureParser


def default_parsers() -> list[ArchitectureParser]:
    return [
        PlantUMLArchitectureParser(),
        JSONArchitectureParser(),
        YAMLArchitectureParser(),
        DrawioArchitectureParser(),
    ]


def load_architecture(path: Path, parsers: Iterable[ArchitectureParser] | None = None) -> ArchitectureModel:
    """Load architecture from disk using the first parser that accepts it."""

    parsers = list(parsers or default_parsers())
    for parser in parsers:
        if parser.can_parse(path):
            return parser.parse(path)
    raise ParserError(f"Unsupported architecture format: {path.suffix}")
