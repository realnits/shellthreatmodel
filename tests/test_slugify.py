from shellthreatmodel.utils.text import slugify


def test_slugify_basic():
    assert slugify("Hello World!") == "hello_world"


def test_slugify_deduplicates_invalid_chars():
    assert slugify("  $$Production-Env!!  ") == "production_env"


def test_slugify_returns_default_when_empty():
    assert slugify("\t\n ") == "artifact"
