"""Helpers for reading and writing analysis artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Sequence

from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.models.threat import DreadScore, StrideCategory, Threat


def load_analysis(path: Path) -> tuple[ArchitectureModel, Sequence[Threat]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    # Pydantic v1/v2 compatibility
    if hasattr(ArchitectureModel, 'model_validate'):
        architecture = ArchitectureModel.model_validate(data["architecture"])
    else:
        architecture = ArchitectureModel.parse_obj(data["architecture"])
    threats = [
        Threat(
            component=item["component"],
            threat=item["threat"],
            stride_category=StrideCategory(item["stride_category"]),
            dread=DreadScore(
                damage=item["dread"]["damage"],
                reproducibility=item["dread"]["reproducibility"],
                exploitability=item["dread"]["exploitability"],
                affected_users=item["dread"]["affected_users"],
                discoverability=item["dread"]["discoverability"],
            ),
            mitigation=item["mitigation"],
            references=tuple(item.get("references", [])),
            methodology=item.get("methodology", "STRIDE/DREAD"),
        )
        for item in data.get("threats", [])
    ]
    return architecture, threats


def serialize_analysis(title: str, architecture: ArchitectureModel, threats: Iterable[Threat]) -> str:
    # Pydantic v1/v2 compatibility
    arch_dict = architecture.model_dump() if hasattr(architecture, 'model_dump') else architecture.dict()
    payload = {
        "title": title,
        "architecture": arch_dict,
        "threats": [
            {
                "component": threat.component,
                "threat": threat.threat,
                "stride_category": threat.stride_category.value,
                "dread": {
                    "damage": threat.dread.damage,
                    "reproducibility": threat.dread.reproducibility,
                    "exploitability": threat.dread.exploitability,
                    "affected_users": threat.dread.affected_users,
                    "discoverability": threat.dread.discoverability,
                    "total": threat.dread.total(),
                    "average": threat.dread.average(),
                    "risk_level": threat.risk_level(),
                },
                "mitigation": threat.mitigation,
                "references": list(threat.references),
                "methodology": threat.methodology,
            }
            for threat in threats
        ],
    }
    return json.dumps(payload, indent=2)
