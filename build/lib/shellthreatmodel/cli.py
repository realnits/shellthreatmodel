"""Command-line interface for ShellThreatModel."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from shellthreatmodel import __version__
from shellthreatmodel.report.generator import render_report as render_single_report
from shellthreatmodel.service import analyze_architecture, render_graph, render_reports, write_analysis_json
from shellthreatmodel.utils.analysis_io import load_analysis
from shellthreatmodel.utils.image_extractor import (
    SUPPORTED_IMAGE_SUFFIXES,
    ImageExtractionError,
    extract_plantuml_from_image,
)
from shellthreatmodel.utils.text import slugify

app = typer.Typer(help="Automate STRIDE/DREAD and PASTA threat modeling from architecture artifacts.")
_console = Console()

SAFE_REPORT_FORMATS = {"markdown", "md", "html", "json"}


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, version: bool = typer.Option(False, "--version", help="Show version and exit.")) -> None:
    if version:
        _console.print(__version__)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        _console.print(ctx.command.get_help(ctx))
        raise typer.Exit()


@app.command()
def analyze(
    architecture_path: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, resolve_path=True, help="Architecture file (PlantUML, JSON, YAML)."),
    mode: str = typer.Option("rules", "--mode", "-m", help="Analysis mode: rules, ai, or pasta."),
    output_dir: Path = typer.Option(Path("threatmodel_output"), "--output-dir", "-o", help="Directory for generated artifacts."),
    report_format: List[str] = typer.Option(["markdown", "html", "json"], "--report-format", "-f", help="Report formats to generate."),
    graph_output: Optional[Path] = typer.Option(None, "--graph-output", "-g", help="Optional path for attack graph export (e.g. graph.png)."),
    skip_reports: bool = typer.Option(False, "--skip-reports", help="Skip report generation (still writes analysis JSON)."),
    openai_model: str = typer.Option("gpt-4o-mini", "--openai-model", help="LLM model for AI mode."),
    openai_api_key: Optional[str] = typer.Option(None, "--openai-api-key", envvar="OPENAI_API_KEY", help="API key for AI mode."),
    openai_base_url: Optional[str] = typer.Option(None, "--openai-base-url", help="Override OpenAI-compatible base URL."),
    temperature: float = typer.Option(0.1, "--temperature", help="Sampling temperature for AI mode."),
    extract_from_image: bool = typer.Option(False, "--from-image", help="Treat input as a diagram image and auto-convert via vision model."),
    vision_model: str = typer.Option("gpt-4.1-mini", "--vision-model", help="Vision model used for image-to-PlantUML conversion."),
    vision_temperature: float = typer.Option(0.1, "--vision-temperature", help="Sampling temperature for vision extraction."),
) -> None:
    """Run threat analysis (rules, AI-assisted, or PASTA) against the provided architecture."""

    output_dir = output_dir.expanduser().resolve()
    report_formats = [fmt.lower() for fmt in report_format]
    unsupported = sorted(set(report_formats) - SAFE_REPORT_FORMATS)
    if unsupported:
        _console.print(f"[red]Unsupported report formats: {', '.join(unsupported)}[/red]")
        raise typer.Exit(code=2)

    output_dir.mkdir(parents=True, exist_ok=True)

    engine_kwargs: dict[str, object] = {}
    if mode.lower() == "ai":
        if openai_api_key:
            engine_kwargs["api_key"] = openai_api_key
        if openai_base_url:
            engine_kwargs["base_url"] = openai_base_url
        engine_kwargs["model"] = openai_model
        engine_kwargs["temperature"] = temperature

    image_suffix = architecture_path.suffix.lower()
    if extract_from_image or image_suffix in SUPPORTED_IMAGE_SUFFIXES:
        if not openai_api_key:
            _console.print("[red]OPENAI_API_KEY is required for image extraction.[/red]")
            raise typer.Exit(code=2)
        try:
            plantuml_text = extract_plantuml_from_image(
                architecture_path,
                api_key=openai_api_key,
                model=vision_model,
                base_url=openai_base_url,
                temperature=vision_temperature,
            )
        except ImageExtractionError as exc:
            _console.print(f"[red]Image extraction failed: {exc}[/red]")
            raise typer.Exit(code=1)

        architecture_filename = f"{architecture_path.stem}_extracted.puml"
        extracted_path = output_dir / architecture_filename
        extracted_path.write_text(plantuml_text, encoding="utf-8")
        _console.print(f"[cyan]Extracted PlantUML saved to[/cyan] {extracted_path}")
        architecture_path = extracted_path

    try:
        architecture, threats = analyze_architecture(architecture_path, mode, **engine_kwargs)
    except Exception as exc:  # pragma: no cover - CLI surface
        _console.print(f"[red]Analysis failed: {exc}[/red]")
        raise typer.Exit(code=1)

    slug = slugify(architecture.title or architecture_path.stem)
    analysis_path = output_dir / f"{slug}_analysis.json"
    write_analysis_json(architecture, threats, analysis_path)

    generated_reports: list[Path] = []
    if not skip_reports and report_formats:
        generated_reports = render_reports(architecture, threats, title=architecture.title, formats=report_formats, output_dir=output_dir)

    graph_path: Optional[Path] = None
    if graph_output:
        graph_output = graph_output.expanduser()
        if not graph_output.is_absolute():
            graph_output = (output_dir / graph_output).resolve()
        graph_path = render_graph(architecture, threats, graph_output)

    _console.print(f"[green]Threat modeling complete for[/green] [bold]{architecture.title}[/bold]")
    _render_summary(threats)

    _console.print(f"[cyan]Analysis JSON:[/cyan] {analysis_path}")
    if generated_reports:
        _console.print("[cyan]Reports:[/cyan]")
        for path in generated_reports:
            _console.print(f"  • {path}")
    if graph_path:
        _console.print(f"[cyan]Attack graph:[/cyan] {graph_path}")


@app.command()
def report(
    analysis_path: Path = typer.Argument(..., exists=True, resolve_path=True, help="Existing analysis JSON from `analyze`."),
    format: str = typer.Option("html", "--format", "-f", help="Report format (markdown, html, json)."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path."),
) -> None:
    """Generate a report from a previously saved analysis."""

    format_key = format.lower()
    if format_key not in SAFE_REPORT_FORMATS:
        _console.print(f"[red]Unsupported format: {format}[/red]")
        raise typer.Exit(code=2)

    architecture, threats = load_analysis(analysis_path)

    if output is None:
        slug = slugify(architecture.title)
        extension = {
            "markdown": ".md",
            "md": ".md",
            "html": ".html",
            "json": ".json",
        }[format_key]
        output = analysis_path.parent / f"{slug}_threats{extension}"
    output = output.resolve()

    generated_path = render_single_report(
        architecture,
        threats,
        format_key,
        title=architecture.title,
        output_path=output,
    )
    _console.print(f"[green]Report generated:[/green] {generated_path}")


@app.command()
def visualize(
    analysis_path: Path = typer.Option(Path("threatmodel_output/analysis.json"), "--analysis", "-a", help="Analysis JSON to visualize."),
    output: Path = typer.Option(..., "--output", "-o", help="Attack graph image path (png, svg, etc.)."),
) -> None:
    """Export an attack graph from an analysis JSON."""

    analysis_path = analysis_path.resolve()
    if not analysis_path.exists():
        _console.print(f"[red]Analysis file not found: {analysis_path}[/red]")
        raise typer.Exit(code=2)

    architecture, threats = load_analysis(analysis_path)
    output = output.expanduser()
    if not output.is_absolute():
        output = analysis_path.parent / output
    render_graph(architecture, threats, output)
    _console.print(f"[green]Attack graph written to[/green] {output}")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="API bind address."),
    port: int = typer.Option(8000, "--port", help="API port."),
    reload: bool = typer.Option(False, "--reload", help="Enable autoreload (development only)."),
) -> None:
    """Launch the FastAPI service for SaaS integrations."""

    try:
        import uvicorn
        from shellthreatmodel.api.server import app as api_app
    except ImportError as exc:  # pragma: no cover - optional dependency
        _console.print(f"[red]Cannot start API server: {exc}[/red]")
        raise typer.Exit(code=1)

    uvicorn.run(api_app, host=host, port=port, reload=reload)


def _render_summary(threats: List) -> None:
    if not threats:
        _console.print("[yellow]No threats identified.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component", style="cyan", overflow="fold")
    table.add_column("Threat", overflow="fold")
    table.add_column("STRIDE", style="green")
    table.add_column("Risk", style="bold")

    for threat in threats:
        table.add_row(threat.component, threat.threat, threat.stride_category.value, threat.risk_level())
    _console.print(table)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    app()
