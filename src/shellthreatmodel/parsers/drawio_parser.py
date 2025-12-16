"""Parser for draw.io (diagrams.net) architecture diagrams."""

from __future__ import annotations

import base64
import html
import re
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable
import zlib

from shellthreatmodel.models.architecture import ArchitectureModel, Component, DataFlow, TrustBoundary
from shellthreatmodel.parsers.base import ArchitectureParser, ParserError

_SUPPORTED_SUFFIXES = {".drawio", ".dio", ".drawio.xml", ".dio.xml"}
_HTML_TAG_RE = re.compile(r"<[^>]+>")


class DrawioArchitectureParser(ArchitectureParser):
    """Parse draw.io diagrams into the unified architecture model."""

    def can_parse(self, path: Path) -> bool:
        name = path.name.lower()
        return any(name.endswith(suffix) for suffix in _SUPPORTED_SUFFIXES)

    def parse(self, path: Path) -> ArchitectureModel:
        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:  # pragma: no cover - defensive
            raise ParserError(f"File not found: {path}") from exc

        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid draw.io XML: {exc}") from exc

        diagram = root.find("diagram")
        if diagram is None:
            raise ParserError("draw.io file missing <diagram> element")

        raw_payload = (diagram.text or "").strip()
        if raw_payload:
            graph_xml = _decode_diagram(raw_payload)
        elif list(diagram):
            graph_xml = ET.tostring(diagram[0], encoding="unicode")
        else:
            raise ParserError("Empty draw.io diagram payload")
        try:
            graph_root = ET.fromstring(graph_xml)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid diagram payload: {exc}") from exc

        cells = list(graph_root.findall(".//mxCell"))
        if not cells:
            raise ParserError("No mxCell elements found in diagram")

        components = []
        flows = []
        boundaries: list[TrustBoundary] = []

        id_to_name: dict[str, str] = {}
        component_parents: dict[str, str] = {}
        boundary_cells: dict[str, tuple[str, str]] = {}

        for cell in cells:
            cell_id = cell.attrib.get("id")
            if not cell_id:
                continue
            style = cell.attrib.get("style", "")
            value = _clean_label(cell.attrib.get("value"))
            parent = cell.attrib.get("parent")

            if cell.attrib.get("vertex") == "1":
                if _is_boundary(style):
                    boundary_cells[cell_id] = (value or f"Boundary {cell_id}", style)
                    continue

                name = value or f"Component {cell_id}"
                comp_type = _infer_component_type(style, name)
                metadata = {"style": style}
                if parent:
                    component_parents[cell_id] = parent
                components.append(Component(name=name, type=comp_type, description=value or None, metadata=metadata))
                id_to_name[cell_id] = name
                continue

            if cell.attrib.get("edge") == "1":
                source = cell.attrib.get("source")
                target = cell.attrib.get("target")
                if not source or not target:
                    continue
                if source not in id_to_name or target not in id_to_name:
                    continue
                flows.append(
                    DataFlow(
                        source=id_to_name[source],
                        destination=id_to_name[target],
                        description=value or None,
                        metadata={"style": style},
                        sensitive=False,
                    )
                )

        if not components and not flows:
            raise ParserError("Unable to extract components or flows from draw.io diagram")

        for boundary_id, (label, style) in boundary_cells.items():
            members = [id_to_name[c_id] for c_id, parent in component_parents.items() if parent == boundary_id]
            if not members:
                continue
            boundaries.append(
                TrustBoundary(
                    name=label,
                    description=None,
                    components=members,
                )
            )

        return ArchitectureModel(
            title=path.stem,
            components=components,
            data_flows=flows,
            trust_boundaries=boundaries,
            metadata={"source": "drawio"},
        )


def _decode_diagram(payload: str) -> str:
    text = payload.strip()
    if not text:
        raise ParserError("Empty draw.io diagram payload")

    if text.startswith("<mxGraphModel"):
        return text

    try:
        decoded = base64.b64decode(text)
    except Exception as exc:  # pragma: no cover - fallback when not base64
        raise ParserError("draw.io diagram is not valid base64 data") from exc

    for wbits in (-15, 15, zlib.MAX_WBITS):  # try raw DEFLATE then default
        try:
            decompressed = zlib.decompress(decoded, wbits)
            text = decompressed.decode("utf-8")

            # diagrams.net commonly stores an encodeURIComponent()-encoded XML string
            # before compression, which yields output starting with "%3CmxGraphModel".
            stripped = text.lstrip()
            if stripped.startswith("%3C") or stripped.startswith("%3c"):
                text = urllib.parse.unquote(text)

            # Some exporters may additionally HTML-escape the model.
            stripped = text.lstrip()
            if stripped.startswith("&lt;"):
                text = html.unescape(text)

            return text
        except zlib.error:
            continue
    raise ParserError("Unable to decompress draw.io diagram payload")


def _clean_label(value: str | None) -> str:
    if not value:
        return ""
    value = html.unescape(value)
    value = _HTML_TAG_RE.sub(" ", value)
    return " ".join(value.split()).strip()


def _is_boundary(style: str) -> bool:
    lowered = style.lower()
    keywords = ("swimlane", "group", "container", "boundary", "pool")
    return any(keyword in lowered for keyword in keywords)


def _infer_component_type(style: str, label: str) -> str:
    lowered_style = style.lower()
    lowered_label = label.lower()
    if "database" in lowered_style or "datastore" in lowered_style or "db" in lowered_label:
        return "database"
    if "queue" in lowered_style or "queue" in lowered_label:
        return "queue"
    if "cloud" in lowered_style or "cloud" in lowered_label:
        return "cloud"
    if "storage" in lowered_style:
        return "storage"
    if "api" in lowered_label:
        return "api"
    if "service" in lowered_label or "svc" in lowered_label:
        return "service"
    return "component"
