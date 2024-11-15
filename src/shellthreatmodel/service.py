"""Core service functions orchestrating parsing, threat generation, and reporting."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

from shellthreatmodel.engines.base import ThreatEngine
from shellthreatmodel.engines.rules_engine import RulesThreatEngine
from shellthreatmodel.engines.pasta_engine import PASTAThreatEngine
from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.models.threat import Threat
from shellthreatmodel.report.generator import render_report
from shellthreatmodel.utils.loader import load_architecture
from shellthreatmodel.visualization.graph import export_attack_graph


def get_engine(mode: str, **engine_kwargs) -> ThreatEngine:
    mode = mode.lower()
    if mode == "ai":
        from shellthreatmodel.engines.ai_engine import AIThreatEngine

        return AIThreatEngine(**engine_kwargs)
    if mode in {"rules", "deterministic", "non-ai"}:
        return RulesThreatEngine()
    if mode in {"pasta", "pasta7"}:
        return PASTAThreatEngine()
    raise ValueError(f"Unsupported mode: {mode}")


def analyze_architecture(path: Path, mode: str, **engine_kwargs) -> tuple[ArchitectureModel, Sequence[Threat]]:
    architecture = load_architecture(path)
    engine = get_engine(mode, **engine_kwargs)
    threats = list(engine.generate(architecture))
    return architecture, threats


def write_analysis_json(architecture: ArchitectureModel, threats: Sequence[Threat], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    from shellthreatmodel.utils.analysis_io import serialize_analysis

    output_path.write_text(
        serialize_analysis(architecture.title, architecture, threats),
        encoding="utf-8",
    )
    return output_path


def render_reports(architecture: ArchitectureModel, threats: Sequence[Threat], *, title: str, formats: Iterable[str], output_dir: Path) -> list[Path]:
    outputs: list[Path] = []
    for format in formats:
        extension = {
            "markdown": ".md",
            "html": ".html",
            "json": ".json",
        }.get(format.lower(), f".{format.lower()}")
        path = output_dir / f"{architecture.title.replace(' ', '_').lower()}_threats{extension}"
        outputs.append(render_report(architecture, threats, format, title=title, output_path=path))
    return outputs


def render_graph(architecture: ArchitectureModel, threats: Sequence[Threat], output_path: Path) -> Path:
    return export_attack_graph(architecture, threats, output_path)
