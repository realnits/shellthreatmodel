"""Parser for YAML architecture artifacts."""

from __future__ import annotations

from pathlib import Path

import yaml

from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.parsers.base import ArchitectureParser, ParserError
from shellthreatmodel.parsers.json_parser import _into_model, _validator


class YAMLArchitectureParser(ArchitectureParser):
    """Parse YAML architecture definitions into the shared model."""

    extensions = {".yaml", ".yml"}

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions

    def parse(self, path: Path) -> ArchitectureModel:
        if not path.exists():
            raise ParserError(f"File not found: {path}")
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if not isinstance(data, dict):
            raise ParserError("YAML root must be a mapping")
        errors = sorted(_validator.iter_errors(data), key=lambda e: e.path)
        if errors:
            msgs = "; ".join(f"{'/'.join(map(str, err.path)) or 'root'}: {err.message}" for err in errors)
            raise ParserError(f"Invalid architecture YAML: {msgs}")
        return _into_model(data)
