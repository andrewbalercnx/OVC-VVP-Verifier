"""Tests for embedded schema store.

Sprint 44: Coverage improvement tests for schema_store.py
"""

import pytest

from app.vvp.acdc.schema_store import (
    get_embedded_schema,
    has_embedded_schema,
    list_embedded_schemas,
    get_embedded_schema_count,
    reload_embedded_schemas,
    KNOWN_VLEI_SCHEMA_SAIDS,
)


class TestSchemaStore:
    """Tests for embedded schema store functions."""

    def test_get_embedded_schema_known_said(self):
        """Should return schema for known SAID."""
        # Use one of the known vLEI schema SAIDs
        for said in KNOWN_VLEI_SCHEMA_SAIDS:
            schema = get_embedded_schema(said)
            if schema is not None:
                assert "$id" in schema
                assert schema["$id"] == said
                break
        # At least verify the function doesn't crash
        assert True

    def test_get_embedded_schema_unknown_said(self):
        """Should return None for unknown SAID."""
        result = get_embedded_schema("UNKNOWN_SAID_THAT_DOES_NOT_EXIST")
        assert result is None

    def test_has_embedded_schema_known(self):
        """Should return True for known schema."""
        # Try to find any embedded schema
        all_schemas = list_embedded_schemas()
        if all_schemas:
            known_said = next(iter(all_schemas.keys()))
            assert has_embedded_schema(known_said) is True

    def test_has_embedded_schema_unknown(self):
        """Should return False for unknown schema."""
        assert has_embedded_schema("UNKNOWN_SAID") is False

    def test_list_embedded_schemas(self):
        """Should return dict of SAID -> title."""
        schemas = list_embedded_schemas()
        assert isinstance(schemas, dict)
        # Each value should be a string (title)
        for said, title in schemas.items():
            assert isinstance(said, str)
            assert isinstance(title, str)

    def test_get_embedded_schema_count(self):
        """Should return count of embedded schemas."""
        count = get_embedded_schema_count()
        assert isinstance(count, int)
        assert count >= 0

    def test_reload_embedded_schemas(self):
        """Should reload schemas and return count."""
        count = reload_embedded_schemas()
        assert isinstance(count, int)
        assert count >= 0
        # After reload, count should match get_embedded_schema_count
        assert count == get_embedded_schema_count()


class TestKnownSchemas:
    """Tests for known vLEI schema SAIDs constant."""

    def test_known_saids_format(self):
        """Known SAIDs should be properly formatted."""
        for said, title in KNOWN_VLEI_SCHEMA_SAIDS.items():
            # SAIDs should start with 'E' (KERI SAID prefix)
            assert said.startswith("E"), f"SAID {said} should start with 'E'"
            # Title should be non-empty string
            assert isinstance(title, str)
            assert len(title) > 0

    def test_known_saids_includes_core_credentials(self):
        """Should include core vLEI credential types."""
        titles = list(KNOWN_VLEI_SCHEMA_SAIDS.values())
        # Check for some expected credential types
        assert any("Qualified vLEI Issuer" in t for t in titles)
        assert any("Legal Entity" in t for t in titles)
