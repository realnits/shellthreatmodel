"""FastAPI server exposing threat modeling endpoints."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from shellthreatmodel import __version__
from shellthreatmodel.service import analyze_architecture
from shellthreatmodel.utils.analysis_io import serialize_analysis
from shellthreatmodel.visualization.graph import export_attack_graph

ALLOWED_SUFFIXES = {".puml", ".plantuml", ".uml", ".json", ".yaml", ".yml", ".txt"}
DEFAULT_GRAPH_FORMAT = "png"

app = FastAPI(
    title="ShellThreatModel API",
    version=__version__,
    description="Automated STRIDE/DREAD threat modeling as a service.",
)


class AnalyzeRequest(BaseModel):
    filename: str = Field(..., description="Original filename to infer parser.")
    content: str = Field(..., description="Architecture document contents.")
    mode: str = Field("rules", description="Analysis mode: rules or ai.")
    openai_api_key: Optional[str] = Field(None, description="Optional API key override for AI mode.")
    openai_model: Optional[str] = Field(None, description="Model name for AI mode.")
    openai_base_url: Optional[str] = Field(None, description="Custom OpenAI-compatible endpoint.")
    temperature: float = Field(0.1, ge=0.0, le=1.0, description="Sampling temperature for AI mode.")
    return_graph: bool = Field(False, description="Whether to include an attack graph (base64 encoded).")
    graph_format: str = Field(DEFAULT_GRAPH_FORMAT, description="Image format for the graph (png, svg).")


class AnalyzeResponse(BaseModel):
    analysis: dict
    graph: Optional[str] = Field(None, description="Base64-encoded attack graph in requested format.")


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/version", tags=["meta"])
def version() -> dict[str, str]:
    return {"version": __version__}


@app.post("/analyze", response_model=AnalyzeResponse, tags=["analysis"])
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    suffix = Path(request.filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {suffix}")

    with NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as temp_file:
        temp_file.write(request.content)
        temp_path = Path(temp_file.name)

    try:
        engine_kwargs: dict[str, object] = {}
        if request.mode.lower() == "ai":
            if request.openai_api_key:
                engine_kwargs["api_key"] = request.openai_api_key
            if request.openai_base_url:
                engine_kwargs["base_url"] = request.openai_base_url
            if request.openai_model:
                engine_kwargs["model"] = request.openai_model
            engine_kwargs["temperature"] = request.temperature

        architecture, threats = analyze_architecture(temp_path, request.mode, **engine_kwargs)
        analysis_payload = json.loads(serialize_analysis(architecture.title, architecture, threats))

        graph_b64: Optional[str] = None
        if request.return_graph and threats:
            graph_suffix = f".{request.graph_format.lstrip('.')}" if request.graph_format else f".{DEFAULT_GRAPH_FORMAT}"
            graph_path = temp_path.with_suffix(graph_suffix)
            export_attack_graph(architecture, threats, graph_path)
            graph_b64 = _encode_file(graph_path)
            graph_path.unlink(missing_ok=True)

        return AnalyzeResponse(analysis=analysis_payload, graph=graph_b64)
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - defensive failure path
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        temp_path.unlink(missing_ok=True)


def _encode_file(path: Path) -> str:
    with path.open("rb") as handle:
        return base64.b64encode(handle.read()).decode("ascii")
