"""Parser for architecture diagrams in image format using OCR."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

try:
    from PIL import Image
    import pytesseract
    HAS_OCR = True
except ImportError:
    HAS_OCR = False

from shellthreatmodel.models.architecture import (
    ArchitectureModel,
    Component,
    DataFlow,
    TrustBoundary,
)
from shellthreatmodel.parsers.base import ArchitectureParser, ParserError

_SUPPORTED_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".gif"}

# Keywords to identify components, flows, and boundaries
_COMPONENT_KEYWORDS = [
    "api", "service", "database", "db", "server", "client", "gateway", "proxy",
    "cache", "queue", "worker", "scheduler", "auth", "storage", "bucket",
    "function", "lambda", "container", "pod", "node", "cluster", "load balancer",
    "firewall", "cdn", "web", "app", "mobile", "frontend", "backend"
]

_FLOW_KEYWORDS = ["->", "→", "=>", "-->", "flow", "request", "response", "sends", "calls", "queries"]
_BOUNDARY_KEYWORDS = ["zone", "boundary", "trust", "perimeter", "vpc", "network", "subnet", "public", "private", "dmz"]


class ImageArchitectureParser(ArchitectureParser):
    """Parse architecture diagrams from images using OCR."""

    def can_parse(self, path: Path) -> bool:
        """Check if this parser can handle the file."""
        if not HAS_OCR:
            return False
        return path.suffix.lower() in _SUPPORTED_SUFFIXES

    def parse(self, path: Path) -> ArchitectureModel:
        """Parse an architecture diagram image using OCR."""
        if not HAS_OCR:
            raise ParserError(
                "OCR dependencies not installed. Install with: pip install pillow pytesseract"
            )

        try:
            image = Image.open(path)
        except Exception as exc:
            raise ParserError(f"Failed to open image: {exc}") from exc

        # Extract text using OCR
        try:
            text = pytesseract.image_to_string(image)
        except Exception as exc:
            raise ParserError(f"OCR extraction failed: {exc}") from exc

        if not text or len(text.strip()) < 10:
            raise ParserError("No meaningful text extracted from image")

        # Also try to extract bounding boxes for spatial relationships
        try:
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        except Exception:
            data = None

        # Parse the extracted text
        components = self._extract_components(text, data)
        flows = self._extract_flows(text, components)
        boundaries = self._extract_boundaries(text, components)

        if not components:
            raise ParserError(
                "No components identified in image. Ensure the image contains clear "
                "text labels for system components."
            )

        return ArchitectureModel(
            title=path.stem,
            components=components,
            data_flows=flows,
            trust_boundaries=boundaries,
            metadata={"source": "image-ocr", "extracted_text_length": len(text)},
        )

    def _extract_components(
        self, text: str, data: dict | None
    ) -> list[Component]:
        """Extract components from OCR text."""
        components = []
        lines = text.split("\n")
        seen_names = set()

        for line in lines:
            line = line.strip()
            if not line or len(line) < 3:
                continue

            # Check if line contains component keywords
            lower_line = line.lower()
            component_type = "component"
            
            for keyword in _COMPONENT_KEYWORDS:
                if keyword in lower_line:
                    # Extract the component name (usually the line or part of it)
                    name = line
                    # Clean up common OCR artifacts
                    name = re.sub(r'[^\w\s\-_]', ' ', name).strip()
                    name = ' '.join(name.split())
                    
                    if name and name not in seen_names and len(name) < 100:
                        seen_names.add(name)
                        
                        # Infer component type
                        if any(k in lower_line for k in ["database", "db", "storage", "bucket"]):
                            component_type = "database"
                        elif any(k in lower_line for k in ["api", "gateway", "proxy"]):
                            component_type = "api"
                        elif any(k in lower_line for k in ["queue", "kafka", "rabbitmq", "sqs"]):
                            component_type = "queue"
                        elif any(k in lower_line for k in ["cache", "redis", "memcached"]):
                            component_type = "cache"
                        elif any(k in lower_line for k in ["auth", "identity", "iam"]):
                            component_type = "auth"
                        elif any(k in lower_line for k in ["web", "frontend", "ui"]):
                            component_type = "web"
                        elif any(k in lower_line for k in ["service", "server", "backend"]):
                            component_type = "service"
                        
                        components.append(
                            Component(
                                name=name,
                                type=component_type,
                                description=f"Extracted via OCR",
                            )
                        )
                    break

        # If we found very few components, be more lenient
        if len(components) < 3:
            # Look for lines with capital letters or common naming patterns
            for line in lines:
                line = line.strip()
                if not line or len(line) < 3 or len(line) > 50:
                    continue
                    
                # Look for camelCase, PascalCase, or Title Case
                if re.search(r'[A-Z][a-z]+[A-Z]|^[A-Z][a-z]+\s+[A-Z]', line):
                    name = re.sub(r'[^\w\s\-_]', ' ', line).strip()
                    name = ' '.join(name.split())
                    
                    if name and name not in seen_names:
                        seen_names.add(name)
                        components.append(
                            Component(
                                name=name,
                                type="component",
                                description="Extracted via OCR (heuristic)",
                            )
                        )

        return components

    def _extract_flows(
        self, text: str, components: list[Component]
    ) -> list[DataFlow]:
        """Extract data flows from OCR text."""
        flows = []
        lines = text.split("\n")
        component_names = [c.name.lower() for c in components]

        for line in lines:
            lower_line = line.lower()
            
            # Check for flow indicators
            has_flow = any(keyword in lower_line for keyword in _FLOW_KEYWORDS)
            if not has_flow:
                continue

            # Try to find source and destination components
            source = None
            destination = None
            
            for comp in components:
                if comp.name.lower() in lower_line:
                    if source is None:
                        source = comp.name
                    elif destination is None:
                        destination = comp.name
                        break

            if source and destination and source != destination:
                # Determine protocol if mentioned
                protocol = None
                if any(p in lower_line for p in ["https", "http"]):
                    protocol = "HTTPS" if "https" in lower_line else "HTTP"
                elif any(p in lower_line for p in ["grpc", "rpc"]):
                    protocol = "gRPC"
                elif any(p in lower_line for p in ["rest", "api"]):
                    protocol = "REST"
                
                flows.append(
                    DataFlow(
                        source=source,
                        destination=destination,
                        protocol=protocol,
                        description=line.strip()[:200],
                        sensitive=any(w in lower_line for w in ["sensitive", "pii", "personal", "credential"]),
                    )
                )

        return flows

    def _extract_boundaries(
        self, text: str, components: list[Component]
    ) -> list[TrustBoundary]:
        """Extract trust boundaries from OCR text."""
        boundaries = []
        lines = text.split("\n")

        for line in lines:
            lower_line = line.lower()
            
            # Check for boundary keywords
            has_boundary = any(keyword in lower_line for keyword in _BOUNDARY_KEYWORDS)
            if not has_boundary:
                continue

            # Extract boundary name
            name = line.strip()
            name = re.sub(r'[^\w\s\-_]', ' ', name).strip()
            name = ' '.join(name.split())

            if not name or len(name) < 3:
                continue

            # Try to associate components with this boundary
            # (simple heuristic: components mentioned nearby in text)
            associated_components = []
            for comp in components:
                if comp.name.lower() in lower_line:
                    associated_components.append(comp.name)

            boundaries.append(
                TrustBoundary(
                    name=name,
                    description="Extracted via OCR",
                    components=associated_components,
                )
            )

        return boundaries
