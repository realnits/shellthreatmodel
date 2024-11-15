"""Report generation for threat modeling outputs."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from jinja2 import Environment, FileSystemLoader, select_autoescape

from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.models.threat import Threat
from shellthreatmodel.utils.analysis_io import serialize_analysis

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html", "xml")),
    trim_blocks=True,
    lstrip_blocks=True,
)


class ReportFormat(str):
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"


def render_report(
    architecture: ArchitectureModel,
    threats: Sequence[Threat],
    format: str,
    *,
    title: str,
    output_path: Path,
) -> Path:
    """Render the report in the requested format."""

    format_key = format.lower()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if format_key == ReportFormat.JSON:
        output_path.write_text(serialize_analysis(title, architecture, threats), encoding="utf-8")
        return output_path

    template_name = {
        ReportFormat.MARKDOWN: "report.md.j2",
        "md": "report.md.j2",
        ReportFormat.HTML: "report.html.j2",
    }.get(format_key)
    if not template_name:
        raise ValueError(f"Unsupported report format: {format}")

    template = _env.get_template(template_name)
    rendered = template.render(title=title, threats=list(threats))
    output_path.write_text(rendered, encoding="utf-8")
    return output_path
