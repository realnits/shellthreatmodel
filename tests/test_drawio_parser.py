import base64
import urllib.parse
import zlib
from pathlib import Path

import pytest

from shellthreatmodel.models.architecture import ArchitectureModel
from shellthreatmodel.parsers.drawio_parser import DrawioArchitectureParser, _decode_diagram
from shellthreatmodel.parsers.base import ParserError


def _write_drawio(tmp_path: Path, diagram_body: str, *, base64_encode: bool = False) -> Path:
    if base64_encode:
        compressed = zlib.compress(diagram_body.encode("utf-8"))
        payload = base64.b64encode(compressed).decode("ascii")
    else:
        payload = diagram_body
    xml = f"""
<mxfile>
  <diagram name='Page-1'>
    {payload}
  </diagram>
</mxfile>
"""
    path = tmp_path / "diagram.drawio"
    path.write_text(xml.strip(), encoding="utf-8")
    return path


def _diagram_body() -> str:
    return """
<mxGraphModel>
  <root>
    <mxCell id="0" />
    <mxCell id="1" parent="0" />
    <mxCell id="boundary" value="Public Zone" style="shape=swimlane" vertex="1" parent="1">
      <mxGeometry x="0" y="0" width="100" height="100" as="geometry" />
    </mxCell>
    <mxCell id="api" value="Orders API" style="shape=process" vertex="1" parent="boundary">
      <mxGeometry x="10" y="10" width="80" height="30" as="geometry" />
    </mxCell>
    <mxCell id="db" value="Orders DB" style="shape=database" vertex="1" parent="1">
      <mxGeometry x="200" y="10" width="80" height="30" as="geometry" />
    </mxCell>
    <mxCell id="flow1" value="REST" edge="1" source="api" target="db" parent="1">
      <mxGeometry relative="1" as="geometry">
        <mxPoint x="0" y="0" as="targetPoint" />
      </mxGeometry>
    </mxCell>
  </root>
</mxGraphModel>
""".strip()


def test_parse_drawio_diagram(tmp_path: Path):
    path = _write_drawio(tmp_path, _diagram_body())
    parser = DrawioArchitectureParser()
    assert parser.can_parse(path)

    model = parser.parse(path)
    assert isinstance(model, ArchitectureModel)
    assert {component.name for component in model.components} == {"Orders API", "Orders DB"}
    assert any(boundary.name == "Public Zone" for boundary in model.trust_boundaries)
    assert len(model.data_flows) == 1
    flow = model.data_flows[0]
    assert flow.source == "Orders API"
    assert flow.destination == "Orders DB"
    assert flow.description == "REST"


def test_parse_base64_encoded_diagram(tmp_path: Path):
    path = _write_drawio(tmp_path, _diagram_body(), base64_encode=True)
    parser = DrawioArchitectureParser()
    model = parser.parse(path)
    assert len(model.components) == 2


def test_parse_drawio_encoded_uri_payload(tmp_path: Path):
  # diagrams.net commonly does:
  #   payload = base64(raw_deflate(encodeURIComponent(mxGraphModelXML)))
  xml = _diagram_body()
  encoded = urllib.parse.quote(xml, safe="-_.!~*'()")

  compressor = zlib.compressobj(level=9, wbits=-15)  # raw DEFLATE
  compressed = compressor.compress(encoded.encode("utf-8")) + compressor.flush()
  payload = base64.b64encode(compressed).decode("ascii")

  path = _write_drawio(tmp_path, payload, base64_encode=False)
  parser = DrawioArchitectureParser()
  model = parser.parse(path)
  assert {component.name for component in model.components} == {"Orders API", "Orders DB"}


def test_can_parse_drawio_xml_suffix(tmp_path: Path):
    path = tmp_path / "diagram.drawio.xml"
    path.write_text(_diagram_body(), encoding="utf-8")
    parser = DrawioArchitectureParser()
    assert parser.can_parse(path)


def test_decode_diagram_invalid_payload():
    with pytest.raises(ParserError):
        _decode_diagram("invalid@@@")
