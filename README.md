# ShellThreatModel

[![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-proprietary-orange.svg)](#license)
[![tests](https://img.shields.io/badge/tests-pytest-lightgrey.svg)](tests/)

> Automate STRIDE/DREAD and PASTA threat modeling directly from architecture diagrams or structured design manifests.

ShellThreatModel delivers production-ready threat models from PlantUML, draw.io, JSON, YAML, and even raw architecture images. It ships a deterministic rules engine, a seven-stage PASTA engine, and optional LLM augmentation, producing actionable reports and attack graphs for security teams.

<details>
<summary><strong>Table of Contents</strong></summary>

- [Key Features](#key-features)
- [Installation](#installation)
  - [Development Setup](#development-setup)
- [Quick Start](#quick-start)
- [Engines at a Glance](#engines-at-a-glance)
- [Working with Diagrams](#working-with-diagrams)
- [Reports and Outputs](#reports-and-outputs)
- [FastAPI Service](#fastapi-service)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Project Roadmap](#project-roadmap)
- [Development Workflow](#development-workflow)
- [FAQ](#faq)
- [License](#license)

</details>

## Key Features

- **Universal parsing** – unify PlantUML, draw.io (diagrams.net), JSON, and YAML into a canonical architecture model.
- **Vision-to-PlantUML** – convert PNG/JPEG/SVG/PDF diagrams to PlantUML via OpenAI vision (optional).
- **Multiple engines** – deterministic STRIDE/DREAD rules, seven-step PASTA methodology, or LLM-assisted heuristics.
- **Rich outputs** – Markdown, HTML, JSON findings plus DREAD metrics, mitigations, and optional Graphviz attack graphs.
- **API ready** – expose analyses via a FastAPI service for CI pipelines or SaaS workflows.
- **Deployment friendly** – Typer-based CLI, Docker/PyInstaller compatible packaging, and GitHub Actions integration.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

ShellThreatModel targets Python 3.11+. Graphviz is recommended if you plan to render attack graphs (`brew install graphviz` on macOS).

### Development Setup

```bash
pip install -e .[dev]
pre-commit install
```

Run the full test suite with `pytest` and format using `ruff format` / `ruff check` if configured.

## Quick Start

```bash
# Deterministic STRIDE/DREAD analysis
shellthreatmodel analyze demo.puml --mode rules --output-dir reports/

# Seven-stage PASTA methodology
shellthreatmodel analyze demo.puml --mode pasta --output-dir reports/

# AI-augmented analysis (requires OPENAI_API_KEY)
shellthreatmodel analyze demo.puml --mode ai --openai-model gpt-4o-mini

# draw.io diagram (diagrams.net) imports
shellthreatmodel analyze diagram.drawio --mode rules

# Auto-extract from an architecture image (requires OPENAI_API_KEY)
shellthreatmodel analyze diagram.png --mode rules --from-image
```

Each run produces an `*_analysis.json` file plus Markdown, HTML, and JSON report variants in the chosen output directory. Attach `--graph-output graph.png` to emit a Graphviz attack graph.

## Engines at a Glance

| Mode  | Description | When to Use |
|-------|-------------|-------------|
| `rules` | Deterministic STRIDE/DREAD rules with DREAD scoring and mitigations. | Baseline assessments, CI/CD automation. |
| `pasta` | Seven-stage PASTA methodology with data-flow awareness and methodology tagging. | Deep-dive risk analysis for complex systems. |
| `ai` | LLM-assisted enrichment (OpenAI compatible). | Exploratory analysis, narrative-rich findings. |

Switch engines per invocation (`--mode`) or mix outputs across different diagrams to compare methodologies.

## Working with Diagrams

- **PlantUML / Text manifests** – pass the `.puml`, `.json`, or `.yaml` file directly.
- **draw.io XML** – the parser recognises `.drawio`, `.drawio.xml`, `.dio`, and `.dio.xml` exports.
- **Images** – supply `--from-image` alongside any supported image format; ShellThreatModel will invoke the vision pipeline to transcribe and then analyse.
- **Trust boundaries & flows** – ensure swimlanes, groups, and connectors are labelled in draw.io for richer PASTA outputs.

Use `shellthreatmodel report analysis.json --format html` to regenerate a single report or `shellthreatmodel visualize --analysis analysis.json --output graph.png` for custom graph renders.

## Reports and Outputs

Artifacts are emitted as:

- `*_analysis.json` – canonical threat payload with STRIDE/DREAD metadata and methodology provenance.
- `*_threats.md` / `*_threats.html` – human-readable reports suitable for PR comments or portals.
- `graph.png` (optional) – Graphviz attack graph when `--graph-output` is provided.

Integrate the JSON payload with downstream tooling or upload the HTML report directly to GitHub Pages or internal portals.

## FastAPI Service

Spin up the API server for programmatic access or SaaS integrations:

```bash
shellthreatmodel serve --host 127.0.0.1 --port 9000
```

Send an analysis request:

```bash
curl -X POST http://127.0.0.1:9000/analyze \
  -H 'Content-Type: application/json' \
  -d '{
        "filename": "diagram.puml",
        "content": "@startuml...",
        "mode": "rules",
        "return_graph": true
      }'
```

The API responds with the JSON threat report and (if requested) a base64-encoded attack graph.


## Configuration

Environment variables:

- `OPENAI_API_KEY` – enables AI and vision-powered flows.
- `OPENAI_MODEL` – optional default model override.
- `SHELLTHREATMODEL_OUTPUT_DIR` – default output location for CLI runs.

CLI flags mirror environment variables (`--openai-model`, `--output-dir`, etc.) for one-off overrides.

## Security Considerations

- Strict content-type validation guards against unsupported file types; pair with container isolation for untrusted uploads.
- AI mode never persists API keys; supply per invocation or set ephemeral environment variables.
- When exposing the FastAPI service, add authentication, rate limiting, and logging scrubbing to match organisational policy.


## Project Roadmap

| Timeline | Focus |
|----------|-------|
| Week 1 | CLI skeleton, PlantUML/JSON/YAML parsers, baseline tests. |
| Week 2 | STRIDE/DREAD engine, report templates, graph exports. |
| Week 3 | LLM integration, prompt tuning, API hardening. |
| Week 4 | CI/CD polish (GitHub Actions), Docker/PyInstaller, SaaS-ready FastAPI deployment hooks. |

## Development Workflow

```bash
pytest
ruff check .
ruff format .
```

- Update or add test fixtures in `tests/` alongside new features.
- Use feature branches and pull requests; include report screenshots or JSON snippets when relevant.
- Publish Docker/PyInstaller artifacts via CI before tagging a release.

## FAQ

**Does ShellThreatModel require internet access?**

- Only AI and vision modes call external APIs. Deterministic STRIDE/DREAD and PASTA analyses run entirely offline.

**Can I integrate with GitHub Actions?**

- Yes. Install the package, run `shellthreatmodel analyze ...`, and upload generated reports as artifacts or PR comments.

**How do I customise mitigations or rules?**

- Extend the rules engine tables under `src/shellthreatmodel/engines` or overlay custom YAML rulepacks and pass them via CLI.

## License

Proprietary – internal use only. Update `pyproject.toml` if you plan to distribute externally.
