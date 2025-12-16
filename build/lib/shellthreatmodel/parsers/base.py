"""Base classes for architecture parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from shellthreatmodel.models.architecture import ArchitectureModel


class ParserError(RuntimeError):
    """Raised when parsing fails."""


class ArchitectureParser(ABC):
    """Common interface for loading architecture artifacts."""

    @abstractmethod
    def can_parse(self, path: Path) -> bool:
        """Return True if this parser can handle the provided file."""

    @abstractmethod
    def parse(self, path: Path) -> ArchitectureModel:
        """Parse the file into an ArchitectureModel."""
