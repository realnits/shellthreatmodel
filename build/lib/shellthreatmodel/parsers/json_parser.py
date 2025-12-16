"""Parser for JSON architecture documents."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from shellthreatmodel.models.architecture import ArchitectureModel, Component, DataFlow, TrustBoundary
from shellthreatmodel.parsers.base import ArchitectureParser, ParserError


_ARCH_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["title", "components", "data_flows"],
    "properties": {
        "title": {"type": "string", "minLength": 1},
        "metadata": {"type": "object", "additionalProperties": {"type": "string"}},
        "components": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "type": {"type": "string"},
                    "description": {"type": "string"},
                    "metadata": {"type": "object", "additionalProperties": {"type": "string"}},
                },
            },
        },
        "data_flows": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["source", "destination"],
                "properties": {
                    "source": {"type": "string"},
                    "destination": {"type": "string"},
                    "protocol": {"type": "string"},
                    "description": {"type": "string"},
                    "sensitive": {"type": "boolean"},
                    "metadata": {"type": "object", "additionalProperties": {"type": "string"}},
                },
            },
        },
        "trust_boundaries": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "components": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
    },
    "additionalProperties": False,
}

_validator = Draft202012Validator(_ARCH_SCHEMA)


class JSONArchitectureParser(ArchitectureParser):
    """Parse JSON architecture overview files."""

    extensions = {".json"}

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions

    def parse(self, path: Path) -> ArchitectureModel:
        if not path.exists():
            raise ParserError(f"File not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        errors = sorted(_validator.iter_errors(data), key=lambda e: e.path)
        if errors:
            msgs = "; ".join(f"{'/'.join(map(str, err.path)) or 'root'}: {err.message}" for err in errors)
            raise ParserError(f"Invalid architecture JSON: {msgs}")
        return _into_model(data)


def _into_model(payload: dict) -> ArchitectureModel:
    components = [Component(**component) for component in payload.get("components", [])]
    flows = [DataFlow(**flow) for flow in payload.get("data_flows", [])]
    boundaries = [TrustBoundary(**boundary) for boundary in payload.get("trust_boundaries", [])]
    return ArchitectureModel(
        title=payload["title"],
        components=components,
        data_flows=flows,
        trust_boundaries=boundaries,
        metadata=payload.get("metadata", {}),
    )
