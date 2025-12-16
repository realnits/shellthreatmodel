"""Vision-assisted extraction of architecture diagrams into PlantUML."""

from __future__ import annotations

import base64
import mimetypes
from pathlib import Path
from typing import Optional

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None  # type: ignore

DEFAULT_VISION_MODEL = "gpt-4.1-mini"
SUPPORTED_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".svg", ".pdf"}
DEFAULT_PROMPT = (
    "You are a security architect. Convert this architecture diagram into a PlantUML component "
    "diagram capturing components, data flows, and trust boundaries. Use @startuml/@enduml, "
    "component/node/database notation, and include directions for interactions."
)


class ImageExtractionError(RuntimeError):
    """Raised when diagram interpretation fails."""


def extract_plantuml_from_image(
    image_path: Path,
    *,
    api_key: str,
    model: str = DEFAULT_VISION_MODEL,
    base_url: str | None = None,
    prompt: str | None = None,
    temperature: float = 0.1,
    max_tokens: int = 1500,
) -> str:
    """Use an OpenAI vision model to convert an architecture diagram image into PlantUML."""

    if OpenAI is None:
        raise ImageExtractionError("openai package is required for image extraction")
    if not api_key:
        raise ImageExtractionError("OPENAI_API_KEY is required for image extraction")

    mime_type, _ = mimetypes.guess_type(image_path)
    if not mime_type:
        raise ImageExtractionError(f"Unable to determine mime type for {image_path}")
    if image_path.suffix.lower() not in SUPPORTED_IMAGE_SUFFIXES:
        raise ImageExtractionError(f"Unsupported image format: {image_path.suffix}")

    image_bytes = image_path.read_bytes()
    image_b64 = base64.b64encode(image_bytes).decode("ascii")
    content = [
        {
            "type": "input_text",
            "text": prompt or DEFAULT_PROMPT,
        },
        {
            "type": "input_image",
            "image_url": {"url": f"data:{mime_type};base64,{image_b64}"},
        },
    ]

    client_kwargs: dict[str, object] = {"api_key": api_key}
    if base_url:
        client_kwargs["base_url"] = base_url
    client = OpenAI(**client_kwargs)  # type: ignore[call-arg]

    response = client.responses.create(  # type: ignore[attr-defined]
        model=model,
        input=[
            {
                "role": "system",
                "content": "You are an expert in translating architecture diagrams into PlantUML.",
            },
            {
                "role": "user",
                "content": content,
            },
        ],
        temperature=temperature,
        max_output_tokens=max_tokens,
    )

    try:
        text = response.output[0].content[0].text  # type: ignore[index]
    except (AttributeError, IndexError) as exc:  # pragma: no cover - defensive
        raise ImageExtractionError("Unexpected response format from vision model") from exc

    plantuml = extract_plantuml_block(text)
    if "@startuml" not in plantuml:
        raise ImageExtractionError("Vision model did not return PlantUML output")
    return plantuml


def extract_plantuml_block(output: str) -> str:
    """Return the PlantUML diagram block from model output."""

    start = output.find("@startuml")
    end = output.find("@enduml")
    if start != -1 and end != -1:
        return output[start : end + len("@enduml")]
    return output.strip()
