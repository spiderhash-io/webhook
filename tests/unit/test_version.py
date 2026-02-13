"""Tests for src/__version__.py."""


def test_version_string_is_defined():
    """Verify __version__ is a non-empty string."""
    from src.__version__ import __version__

    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_version_follows_semver_format():
    """Verify version string looks like a semver (major.minor.patch)."""
    from src.__version__ import __version__

    parts = __version__.split(".")
    assert len(parts) >= 2, f"Expected at least major.minor, got {__version__}"
    for part in parts:
        assert part.isdigit(), f"Non-numeric version part: {part}"


def test_author_is_defined():
    """Verify __author__ is a non-empty string."""
    from src.__version__ import __author__

    assert isinstance(__author__, str)
    assert len(__author__) > 0


def test_license_is_defined():
    """Verify __license__ is a non-empty string."""
    from src.__version__ import __license__

    assert isinstance(__license__, str)
    assert len(__license__) > 0


def test_description_is_defined():
    """Verify __description__ is a non-empty string."""
    from src.__version__ import __description__

    assert isinstance(__description__, str)
    assert len(__description__) > 0


def test_url_is_defined():
    """Verify __url__ is a non-empty string with a valid URL prefix."""
    from src.__version__ import __url__

    assert isinstance(__url__, str)
    assert __url__.startswith("http"), f"URL should start with http: {__url__}"


def test_all_attributes_importable():
    """Verify all expected attributes can be imported."""
    import src.__version__ as v

    expected_attrs = ["__version__", "__author__", "__license__", "__description__", "__url__"]
    for attr in expected_attrs:
        assert hasattr(v, attr), f"Missing attribute: {attr}"
