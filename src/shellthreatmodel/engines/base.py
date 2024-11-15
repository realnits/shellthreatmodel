"""Threat generation engines interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.models.threat import Threat


class ThreatEngine(ABC):
    """Common interface all threat engines must implement."""

    name: str

    @abstractmethod
    def generate(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Produce STRIDE/DREAD threats for the given architecture."""


class ThreatEngineError(RuntimeError):
    """Raised when the engine fails to generate threats."""
