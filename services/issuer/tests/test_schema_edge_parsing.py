"""Tests for Sprint 65: Schema Edge Block Parsing.

Tests cover:
- parse_schema_edges() utility function that mirrors JS SchemaEdgeParser
- Edge block structure across all VVP schema JSON files
- Cross-validation between parse_schema_edges() and DOSSIER_EDGE_DEFS
- Edge cases: no edges, reordered oneOf, missing properties
"""

import json
from pathlib import Path

import pytest


# =============================================================================
# Schema SAIDs (must match constants in dossier.py)
# =============================================================================

DOSSIER_SCHEMA_SAID = "EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P"
GCD_SCHEMA_SAID = "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o"
TNALLOC_SCHEMA_SAID = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"


SCHEMAS_DIR = Path(__file__).parent.parent / "app" / "schema" / "schemas"


# =============================================================================
# Python equivalent of JS SchemaEdgeParser.parseEdges()
# =============================================================================


def parse_schema_edges(schema_doc: dict) -> list[dict]:
    """Parse edge slot definitions from a schema JSON document.

    Mirrors the JS SchemaEdgeParser.parseEdges() using type-based oneOf
    detection (NOT index-based).

    Returns:
        List of edge slot dicts with keys: name, required, schemaConstraint,
        operator, description.
    """
    edges_one_of = schema_doc.get("properties", {}).get("e", {}).get("oneOf")
    if not edges_one_of:
        return []

    # Find the object variant by type (not by index)
    edges_obj = next((v for v in edges_one_of if v.get("type") == "object"), None)
    if not edges_obj:
        return []

    required_edges = set(edges_obj.get("required", [])) - {"d"}
    slots = []

    for key, prop in edges_obj.get("properties", {}).items():
        if key == "d":
            continue

        slot = {
            "name": key,
            "required": key in required_edges,
            "schemaConstraint": prop.get("properties", {}).get("s", {}).get("const"),
            "operator": prop.get("properties", {}).get("o", {}).get("const"),
            "description": prop.get("description", ""),
        }
        slots.append(slot)

    # Sort: required first, then alphabetical
    slots.sort(key=lambda s: (not s["required"], s["name"]))
    return slots


def _load_schema(said: str) -> dict:
    """Load a schema JSON file by SAID."""
    path = SCHEMAS_DIR / f"{said}.json"
    assert path.exists(), f"Schema file not found: {path}"
    return json.loads(path.read_text())


# =============================================================================
# Dossier Schema Edge Tests
# =============================================================================


class TestParseDossierSchemaEdges:
    """Tests for parsing the VVP Dossier schema edge block."""

    def test_dossier_schema_has_six_edges(self):
        """Dossier schema defines 6 edge slots."""
        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        assert len(edges) == 6

    def test_dossier_required_edges(self):
        """Dossier schema has 4 required edges: vetting, alloc, tnalloc, delsig."""
        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        required = {e["name"] for e in edges if e["required"]}
        assert required == {"vetting", "alloc", "tnalloc", "delsig"}

    def test_dossier_optional_edges(self):
        """Dossier schema has 2 optional edges: bownr, bproxy."""
        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        optional = {e["name"] for e in edges if not e["required"]}
        assert optional == {"bownr", "bproxy"}

    def test_dossier_alloc_schema_constraint(self):
        """alloc edge has GCD schema constraint."""
        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        alloc = next(e for e in edges if e["name"] == "alloc")
        assert alloc["schemaConstraint"] == GCD_SCHEMA_SAID

    def test_dossier_tnalloc_schema_constraint(self):
        """tnalloc edge has TN Allocation schema constraint."""
        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        tnalloc = next(e for e in edges if e["name"] == "tnalloc")
        assert tnalloc["schemaConstraint"] == TNALLOC_SCHEMA_SAID

    def test_dossier_vetting_no_schema_constraint(self):
        """vetting edge has NO schema constraint (accepts any identity cred)."""
        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        vetting = next(e for e in edges if e["name"] == "vetting")
        assert vetting["schemaConstraint"] is None

    def test_dossier_delsig_schema_constraint(self):
        """delsig edge has GCD schema constraint."""
        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        delsig = next(e for e in edges if e["name"] == "delsig")
        assert delsig["schemaConstraint"] == GCD_SCHEMA_SAID

    def test_dossier_operators(self):
        """Verify operators on dossier edges."""
        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        operators = {e["name"]: e["operator"] for e in edges}
        assert operators["alloc"] == "I2I"
        assert operators["tnalloc"] == "I2I"
        assert operators["vetting"] == "NI2I"
        assert operators["delsig"] == "NI2I"
        assert operators["bownr"] == "NI2I"
        # bproxy has no const on o — may or may not be constrained
        # The schema doesn't constrain bproxy's operator


# =============================================================================
# TNAlloc Schema Edge Tests
# =============================================================================


class TestParseTnallocSchemaEdges:
    """Tests for parsing the TN Allocation schema edge block."""

    def test_tnalloc_has_two_edges(self):
        """TNAlloc schema defines 2 edge slots."""
        schema = _load_schema(TNALLOC_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        assert len(edges) == 2

    def test_tnalloc_required_edge(self):
        """TNAlloc schema has 1 required edge: tnalloc."""
        schema = _load_schema(TNALLOC_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        required = [e for e in edges if e["required"]]
        assert len(required) == 1
        assert required[0]["name"] == "tnalloc"

    def test_tnalloc_i2i_operator(self):
        """tnalloc edge has I2I operator."""
        schema = _load_schema(TNALLOC_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        tnalloc = next(e for e in edges if e["name"] == "tnalloc")
        assert tnalloc["operator"] == "I2I"


# =============================================================================
# GCD Schema Edge Tests
# =============================================================================


class TestParseGcdSchemaEdges:
    """Tests for parsing the GCD (Cooperative Delegation) schema edge block."""

    def test_gcd_has_one_edge(self):
        """GCD schema defines 1 edge slot."""
        schema = _load_schema(GCD_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        assert len(edges) == 1

    def test_gcd_issuer_edge_required(self):
        """GCD issuer edge is required."""
        schema = _load_schema(GCD_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        assert edges[0]["required"] is True
        assert edges[0]["name"] == "issuer"

    def test_gcd_issuer_i2i(self):
        """GCD issuer edge has I2I operator."""
        schema = _load_schema(GCD_SCHEMA_SAID)
        edges = parse_schema_edges(schema)
        assert edges[0]["operator"] == "I2I"


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestParseSchemaEdgeCases:
    """Tests for edge cases in schema edge parsing."""

    def test_no_edges_property(self):
        """Schema with no 'e' property returns empty list."""
        schema = {"properties": {"a": {"type": "object"}}}
        assert parse_schema_edges(schema) == []

    def test_no_oneof(self):
        """Schema with e but no oneOf returns empty list."""
        schema = {"properties": {"e": {"type": "string"}}}
        assert parse_schema_edges(schema) == []

    def test_oneof_no_object_variant(self):
        """Schema with oneOf but no object variant returns empty list."""
        schema = {"properties": {"e": {"oneOf": [{"type": "string"}]}}}
        assert parse_schema_edges(schema) == []

    def test_empty_properties(self):
        """Schema with empty edge properties returns empty list."""
        schema = {"properties": {"e": {"oneOf": [
            {"type": "object", "properties": {"d": {"type": "string"}}, "required": ["d"]},
        ]}}}
        assert parse_schema_edges(schema) == []

    def test_reordered_oneof(self):
        """Parser works when object variant is at index 0 (not 1)."""
        # Build a schema with object variant first, then string
        schema = {"properties": {"e": {"oneOf": [
            {
                "type": "object",
                "properties": {
                    "d": {"type": "string"},
                    "testEdge": {
                        "type": "object",
                        "properties": {
                            "n": {"type": "string"},
                            "s": {"const": "ESAID123"},
                            "o": {"const": "I2I"},
                        },
                    },
                },
                "required": ["d", "testEdge"],
            },
            {"type": "string", "description": "SAID reference"},
        ]}}}
        edges = parse_schema_edges(schema)
        assert len(edges) == 1
        assert edges[0]["name"] == "testEdge"
        assert edges[0]["required"] is True
        assert edges[0]["schemaConstraint"] == "ESAID123"
        assert edges[0]["operator"] == "I2I"

    def test_empty_schema(self):
        """Empty dict returns empty list."""
        assert parse_schema_edges({}) == []

    def test_d_excluded(self):
        """'d' property is always excluded from edge slots."""
        schema = {"properties": {"e": {"oneOf": [
            {
                "type": "object",
                "properties": {
                    "d": {"type": "string"},
                    "edge1": {"type": "object", "properties": {"n": {"type": "string"}}},
                },
                "required": ["d", "edge1"],
            },
        ]}}}
        edges = parse_schema_edges(schema)
        assert len(edges) == 1
        assert edges[0]["name"] == "edge1"


# =============================================================================
# Cross-validation: parse_schema_edges vs DOSSIER_EDGE_DEFS
# =============================================================================


class TestDossierEdgeDefsCrossValidation:
    """Cross-validate that schema JSON matches DOSSIER_EDGE_DEFS constants."""

    def test_required_flags_match(self):
        """Required/optional flags in schema JSON match DOSSIER_EDGE_DEFS."""
        from app.api.dossier import DOSSIER_EDGE_DEFS

        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        parsed = parse_schema_edges(schema)
        parsed_map = {e["name"]: e for e in parsed}

        for edge_name, edge_def in DOSSIER_EDGE_DEFS.items():
            assert edge_name in parsed_map, f"Edge '{edge_name}' from DOSSIER_EDGE_DEFS not found in schema"
            assert parsed_map[edge_name]["required"] == edge_def["required"], \
                f"Required mismatch for '{edge_name}': schema={parsed_map[edge_name]['required']}, DEFS={edge_def['required']}"

    def test_schema_constraints_match(self):
        """Schema SAID constraints in schema JSON match DOSSIER_EDGE_DEFS."""
        from app.api.dossier import DOSSIER_EDGE_DEFS

        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        parsed = parse_schema_edges(schema)
        parsed_map = {e["name"]: e for e in parsed}

        for edge_name, edge_def in DOSSIER_EDGE_DEFS.items():
            parsed_constraint = parsed_map[edge_name]["schemaConstraint"]
            defs_constraint = edge_def["schema"]
            assert parsed_constraint == defs_constraint, \
                f"Schema constraint mismatch for '{edge_name}': schema={parsed_constraint}, DEFS={defs_constraint}"

    def test_edge_count_matches(self):
        """Number of edges in schema JSON matches DOSSIER_EDGE_DEFS."""
        from app.api.dossier import DOSSIER_EDGE_DEFS

        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        parsed = parse_schema_edges(schema)
        assert len(parsed) == len(DOSSIER_EDGE_DEFS)

    def test_edge_names_match(self):
        """Edge names in schema JSON match DOSSIER_EDGE_DEFS."""
        from app.api.dossier import DOSSIER_EDGE_DEFS

        schema = _load_schema(DOSSIER_SCHEMA_SAID)
        parsed = parse_schema_edges(schema)
        parsed_names = {e["name"] for e in parsed}
        defs_names = set(DOSSIER_EDGE_DEFS.keys())
        assert parsed_names == defs_names
