"""Threat modeling data structures and helpers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, Sequence


class StrideCategory(str, Enum):
    """STRIDE threat categories."""

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass(slots=True)
class DreadScore:
    """Represents a DREAD score across the five factors."""

    damage: int
    reproducibility: int
    exploitability: int
    affected_users: int
    discoverability: int

    def total(self) -> int:
        """Return the summed DREAD value."""

        return self.damage + self.reproducibility + self.exploitability + self.affected_users + self.discoverability

    def average(self) -> float:
        """Return the average DREAD score across five metrics."""

        return self.total() / 5.0


@dataclass(slots=True)
class Threat:
    """Threat record with associated scoring and context."""

    component: str
    threat: str
    stride_category: StrideCategory
    dread: DreadScore
    mitigation: str
    references: tuple[str, ...] = ()
    methodology: str = "STRIDE/DREAD"

    def risk_level(self, thresholds: Sequence[float] | None = None) -> str:
        """Translate the average DREAD score into High/Medium/Low buckets."""

        thresholds = thresholds or (7.5, 5.0)
        avg = self.dread.average()
        if avg >= thresholds[0]:
            return "High"
        if avg >= thresholds[1]:
            return "Medium"
        return "Low"


ThreatGenerator = Callable[[Iterable[Threat]], Iterable[Threat]]
