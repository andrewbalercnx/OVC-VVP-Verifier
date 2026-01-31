"""Tests for SAID computation module."""

import pytest

from app.schema.said import (
    SAIDComputationError,
    SAIDVerificationError,
    compute_schema_said,
    create_schema_template,
    inject_said,
    verify_schema_said,
)


class TestComputeSchemaSAID:
    """Tests for compute_schema_said function."""

    def test_compute_said_returns_44_char_string(self):
        """SAID should be 44 characters (CESR encoded Blake3-256)."""
        schema = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Test Schema",
            "type": "object",
        }
        said = compute_schema_said(schema)
        assert len(said) == 44
        assert said.startswith("E")  # Blake3-256 prefix

    def test_compute_said_deterministic(self):
        """Same schema should produce same SAID."""
        schema = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Test Schema",
            "type": "object",
        }
        said1 = compute_schema_said(schema)
        said2 = compute_schema_said(schema)
        assert said1 == said2

    def test_compute_said_different_for_different_content(self):
        """Different schemas should produce different SAIDs."""
        schema1 = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Schema One",
            "type": "object",
        }
        schema2 = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Schema Two",
            "type": "object",
        }
        said1 = compute_schema_said(schema1)
        said2 = compute_schema_said(schema2)
        assert said1 != said2

    def test_compute_said_missing_id_raises(self):
        """Schema without $id should raise error."""
        schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "No ID Schema",
        }
        with pytest.raises(SAIDComputationError, match="missing required"):
            compute_schema_said(schema)

    def test_compute_said_with_placeholder_id(self):
        """Schema with placeholder $id should work."""
        schema = {
            "$id": "#" * 44,
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Placeholder Schema",
            "type": "object",
        }
        said = compute_schema_said(schema)
        assert len(said) == 44
        assert not said.startswith("#")


class TestInjectSAID:
    """Tests for inject_said function."""

    def test_inject_said_returns_schema_with_said(self):
        """inject_said should return schema with computed $id."""
        schema = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Inject Test",
            "type": "object",
        }
        result = inject_said(schema)
        assert "$id" in result
        assert len(result["$id"]) == 44
        assert result["$id"].startswith("E")

    def test_inject_said_does_not_modify_original(self):
        """inject_said should not modify the original schema."""
        schema = {
            "$id": "original",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Original Test",
            "type": "object",
        }
        result = inject_said(schema)
        assert schema["$id"] == "original"  # Original unchanged
        assert result["$id"] != "original"  # Result has SAID

    def test_inject_said_preserves_other_fields(self):
        """inject_said should preserve all other schema fields."""
        schema = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Preserve Test",
            "description": "A test description",
            "type": "object",
            "properties": {"name": {"type": "string"}},
        }
        result = inject_said(schema)
        assert result["title"] == "Preserve Test"
        assert result["description"] == "A test description"
        assert result["properties"] == {"name": {"type": "string"}}


class TestVerifySchemaSAID:
    """Tests for verify_schema_said function."""

    def test_verify_valid_said_returns_true(self):
        """Verification should return True for valid SAID."""
        schema = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Verify Test",
            "type": "object",
        }
        # Inject proper SAID
        saidified = inject_said(schema)
        assert verify_schema_said(saidified) is True

    def test_verify_invalid_said_returns_false(self):
        """Verification should return False for incorrect SAID."""
        schema = {
            "$id": "EInvalidSAIDthatdoesntmatchcontent123456789",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Invalid Test",
            "type": "object",
        }
        assert verify_schema_said(schema) is False

    def test_verify_missing_id_raises(self):
        """Verification should raise for missing $id."""
        schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "No ID",
        }
        with pytest.raises(SAIDVerificationError, match="missing required"):
            verify_schema_said(schema)

    def test_verify_empty_id_raises(self):
        """Verification should raise for empty $id."""
        schema = {
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Empty ID",
        }
        with pytest.raises(SAIDVerificationError, match="empty or placeholder"):
            verify_schema_said(schema)

    def test_verify_placeholder_id_raises(self):
        """Verification should raise for placeholder $id."""
        schema = {
            "$id": "#" * 44,
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Placeholder ID",
        }
        with pytest.raises(SAIDVerificationError, match="empty or placeholder"):
            verify_schema_said(schema)


class TestCreateSchemaTemplate:
    """Tests for create_schema_template function."""

    def test_create_template_basic(self):
        """Template should have required fields."""
        template = create_schema_template("Test Credential")
        assert template["$id"] == "#" * 44  # Placeholder
        assert template["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert template["title"] == "Test Credential"
        assert template["type"] == "object"

    def test_create_template_with_description(self):
        """Template should include description."""
        template = create_schema_template("Test", description="A test schema")
        assert template["description"] == "A test schema"

    def test_create_template_with_credential_type(self):
        """Template should include credential type."""
        template = create_schema_template("Test", credential_type="LegalEntity")
        assert template["credentialType"] == "LegalEntity"

    def test_create_template_with_custom_properties(self):
        """Template should include custom properties."""
        props = {"customField": {"type": "string"}}
        template = create_schema_template("Test", properties=props)
        assert template["properties"]["a"]["properties"] == props

    def test_create_template_can_be_saidified(self):
        """Template should be valid for SAID injection."""
        template = create_schema_template("Saidify Test")
        result = inject_said(template)
        assert len(result["$id"]) == 44
        assert result["$id"].startswith("E")

    def test_create_template_saidified_verifies(self):
        """Saidified template should verify correctly."""
        template = create_schema_template("Verify Test")
        saidified = inject_said(template)
        assert verify_schema_said(saidified) is True


class TestKnownSchemas:
    """Tests against known vLEI schema SAIDs."""

    # These SAIDs are from the embedded schemas
    KNOWN_SAIDS = {
        "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY": "Legal Entity",
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao": "QVI",
    }

    def test_known_saids_are_valid_format(self):
        """Known SAIDs should have correct format."""
        for said in self.KNOWN_SAIDS.keys():
            assert len(said) == 44
            assert said.startswith("E")  # Blake3-256 prefix
