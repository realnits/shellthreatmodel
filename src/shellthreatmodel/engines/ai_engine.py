"""LLM-backed STRIDE/DREAD threat generator."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Iterable, Sequence

from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.models.threat import DreadScore, StrideCategory, Threat
from shellthreatmodel.engines.base import ThreatEngine, ThreatEngineError

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None  # type: ignore


class AIThreatEngine(ThreatEngine):
    """Threat engine that delegates to an LLM for adaptive threat discovery."""

    name = "ai"

    def __init__(
        self,
        *,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 1200,
    ) -> None:
        if OpenAI is None:
            raise ImportError("openai package is required for AI mode")
        api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ThreatEngineError("OPENAI_API_KEY not configured")
        client_params = {"api_key": api_key}
        if base_url:
            client_params["base_url"] = base_url
        self._client = OpenAI(**client_params)  # type: ignore[arg-type]
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens

    def generate(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        prompt = self._build_prompt(architecture)
        response = self._client.responses.create(  # type: ignore[call-arg]
            model=self._model,
            input=[
                {
                    "role": "system",
                    "content": "You are a security architect specializing in STRIDE/DREAD threat modeling.",
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=self._temperature,
            max_output_tokens=self._max_tokens,
        )
        try:
            text = response.output[0].content[0].text  # type: ignore[index]
        except (AttributeError, IndexError) as exc:  # pragma: no cover - defensive
            raise ThreatEngineError(f"Unexpected LLM response structure: {response}") from exc
        return self._parse_response(text)

    def _build_prompt(self, architecture: ArchitectureModel) -> str:
        payload = {
            "title": architecture.title,
            "components": [component.model_dump() for component in architecture.components],
            "data_flows": [flow.model_dump() for flow in architecture.data_flows],
            "trust_boundaries": [boundary.model_dump() for boundary in architecture.trust_boundaries],
        }
        return (
            "You are a security architect. Given this architecture JSON, produce STRIDE threats with DREAD scoring.\n"
            "Return a JSON array where each item matches this schema: {"""{"component": "...", "threat": "...", "stride_category": "...", "dread_score": {"damage": int, "reproducibility": int, "exploitability": int, "affected_users": int, "discoverability": int}, "mitigation": "...", "references": ["..."]}"""}.\n"
            "All DREAD values must be integers between 0 and 10.\n"
            "Architecture JSON:\n"
            f"{json.dumps(payload, indent=2)}"
        )

    def _parse_response(self, text: str) -> Sequence[Threat]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ThreatEngineError("LLM response was not valid JSON") from exc
        if not isinstance(data, list):
            raise ThreatEngineError("LLM response must be a JSON list")
        threats: list[Threat] = []
        for item in data:
            try:
                threats.append(_into_threat(item))
            except Exception as exc:  # pragma: no cover - defensive conversion
                raise ThreatEngineError(f"Invalid threat payload: {item}") from exc
        return threats


def _into_threat(item: dict) -> Threat:
    dread_payload = item.get("dread_score", {})
    dread = DreadScore(
        damage=int(dread_payload["damage"]),
        reproducibility=int(dread_payload["reproducibility"]),
        exploitability=int(dread_payload["exploitability"]),
        affected_users=int(dread_payload["affected_users"]),
        discoverability=int(dread_payload["discoverability"]),
    )
    references = tuple(item.get("references", []))
    category = StrideCategory(item["stride_category"])
    return Threat(
        component=item["component"],
        threat=item["threat"],
        stride_category=category,
        dread=dread,
        mitigation=item["mitigation"],
        references=references,
    )
