from shellthreatmodel.engines.rules_engine import RulesThreatEngine
from shellthreatmodel.models.architecture import ArchitectureModel, Component, DataFlow, TrustBoundary
from shellthreatmodel.models.threat import StrideCategory


def test_rules_engine_generates_expected_threats():
    architecture = ArchitectureModel(
        title="Payment Service",
        components=[
            Component(name="Auth API", type="api"),
            Component(name="Payment DB", type="database"),
        ],
        data_flows=[
            DataFlow(
                source="Auth API",
                destination="Payment DB",
                description="Store user tokens",
                protocol="http",
                sensitive=True,
            )
        ],
        trust_boundaries=[
            TrustBoundary(name="Public Zone", components=["Auth API"]),
            TrustBoundary(name="Private Zone", components=["Payment DB"]),
        ],
    )

    engine = RulesThreatEngine()
    threats = list(engine.generate(architecture))

    categories = {threat.stride_category for threat in threats}

    assert StrideCategory.TAMPERING in categories
    assert StrideCategory.INFORMATION_DISCLOSURE in categories
    assert StrideCategory.SPOOFING in categories
