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
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


class AIThreatEngine(ThreatEngine):
    """Threat engine that delegates to Gemini 2.5 Pro via apiGPTeal for adaptive threat discovery."""

    name = "ai"

    def __init__(
        self,
        *,
        model: str = "gemini-2-5-pro",
        api_key: str | None = None,
        base_url: str = "https://iapi-test.merck.com/gpt/v2/gemini-2-5-pro",
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> None:
        if requests is None:
            raise ImportError("requests package is required for AI mode")
        api_key = api_key or os.getenv("XMerckAPIKey")
        if not api_key:
            raise ThreatEngineError("XMerckAPIKey not configured")
        self._api_key = api_key
        self._base_url = base_url
        self._temperature = temperature
        self._max_tokens = max_tokens

    def generate(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        prompt = self._build_prompt(architecture)
        
        headers = {
            "Content-Type": "application/json",
            "X-Merck-APIKey": self._api_key
        }
        
        payload = {
            "contents": {
                "role": "user",
                "parts": {
                    "text": prompt
                }
            },
            "safety_settings": {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_LOW_AND_ABOVE"
            },
            "generation_config": {
                "temperature": self._temperature,
                "topP": 0.9,
                "topK": 40,
                "maxOutputTokens": self._max_tokens
            }
        }
        
        try:
            response = requests.post(self._base_url, headers=headers, json=payload)  # type: ignore[union-attr]
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            raise ThreatEngineError(f"API request failed: {exc}") from exc
        
        # Extract text from Gemini response structure
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as exc:
            raise ThreatEngineError(f"Unexpected API response structure: {data}") from exc
        
        return self._parse_response(text)

    def _build_prompt(self, architecture: ArchitectureModel) -> str:
        # Pydantic v1/v2 compatibility
        def to_dict(obj):
            return obj.model_dump() if hasattr(obj, 'model_dump') else obj.dict()
        
        payload = {
            "title": architecture.title,
            "components": [to_dict(component) for component in architecture.components],
            "data_flows": [to_dict(flow) for flow in architecture.data_flows],
            "trust_boundaries": [to_dict(boundary) for boundary in architecture.trust_boundaries],
        }
        return (
            "You are a security architect. Given this architecture JSON, produce STRIDE threats with DREAD scoring.\n"
            'Return a JSON array where each item matches this schema: {"component": "...", "threat": "...", "stride_category": "...", "dread_score": {"damage": int, "reproducibility": int, "exploitability": int, "affected_users": int, "discoverability": int}, "mitigation": "...", "references": ["..."]}.\n'
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
