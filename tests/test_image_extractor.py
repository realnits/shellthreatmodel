from shellthreatmodel.utils.image_extractor import extract_plantuml_block


def test_extract_plantuml_block_trims_surrounding_text():
    raw = """
Some intro text
```plantuml
@startuml
component API
@enduml
```
More commentary
"""
    assert extract_plantuml_block(raw) == "@startuml\ncomponent API\n@enduml"


def test_extract_plantuml_block_returns_trimmed_when_no_markers():
    text = "component API\ncomponent DB"
    assert extract_plantuml_block(text) == "component API\ncomponent DB"
