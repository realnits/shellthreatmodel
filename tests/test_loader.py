from pathlib import Path

import pytest

from shellthreatmodel.parsers.base import ParserError
from shellthreatmodel.utils.loader import load_architecture


@pytest.fixture
def tmp_architecture(tmp_path: Path) -> Path:
    path = tmp_path / "diagram.puml"
    path.write_text(
        """@startuml
component "API" as api
node "DB" as db
api --> db : store data
@enduml
""",
        encoding="utf-8",
    )
    return path


def test_load_architecture_records(tmp_architecture: Path):
    model = load_architecture(tmp_architecture)
    assert model.components
    assert model.data_flows
    assert model.title == "diagram"


def test_load_architecture_rejects_unknown(tmp_path: Path):
    path = tmp_path / "diagram.csv"
    path.write_text("hello", encoding="utf-8")
    with pytest.raises(ParserError):
        load_architecture(path)
