"""Unit tests for edge operator validation (I2I/DI2I/NI2I).

Per ACDC spec, edge operators control authority flow through credential chains:
- I2I: child.issuer == parent.issuee (strict)
- DI2I: child.issuer == parent.issuee OR delegated from parent.issuee
- NI2I: No constraint (permissive, reference-only)

Tests cover:
- I2I constraint validation (positive and negative)
- DI2I delegation chain validation
- NI2I permissive behavior
- Bearer credential handling (no issuee binding)
- Edge format variations (dict vs bare SAID)
- Schema constraint warnings
"""

import pytest

from app.vvp.dossier.models import (
    ACDCNode,
    DossierDAG,
    DossierWarning,
    EdgeOperator,
    EdgeValidationWarning,
    ToIPWarningCode,
)
from app.vvp.dossier.validator import (
    validate_i2i_edge,
    validate_di2i_edge,
    validate_ni2i_edge,
    validate_edge_operator,
    validate_all_edge_operators,
    validate_edge_schema,
    _get_issuee_from_attributes,
)


# =============================================================================
# Test Fixtures
# =============================================================================


def make_acdc_node(
    said: str,
    issuer: str,
    schema: str = "SCHEMA_123",
    issuee: str = None,
    edges: dict = None,
    cred_type: str = None,
) -> ACDCNode:
    """Helper to create ACDCNode for testing."""
    attrs = {}
    if issuee:
        attrs["i"] = issuee
    if cred_type:
        attrs["type"] = cred_type

    return ACDCNode(
        said=said,
        issuer=issuer,
        schema=schema,
        attributes=attrs if attrs else None,
        edges=edges,
        raw={"d": said, "i": issuer, "s": schema},
    )


# =============================================================================
# I2I Operator Tests
# =============================================================================


class TestI2IValidation:
    """Tests for I2I (Issuer-to-Issuee) constraint validation."""

    def test_i2i_valid_when_issuer_equals_issuee(self):
        """I2I passes when child.issuer == parent.issuee."""
        parent = make_acdc_node(
            said="PARENT_SAID",
            issuer="ROOT_AID",
            issuee="CHILD_ISSUER_AID",
        )
        child = make_acdc_node(
            said="CHILD_SAID",
            issuer="CHILD_ISSUER_AID",  # Matches parent issuee
            issuee="LEAF_AID",
        )

        result = validate_i2i_edge(child, parent, "auth")
        assert result is None  # No warning = valid

    def test_i2i_invalid_when_issuer_not_equals_issuee(self):
        """I2I fails when child.issuer != parent.issuee."""
        parent = make_acdc_node(
            said="PARENT_SAID",
            issuer="ROOT_AID",
            issuee="EXPECTED_ISSUER",
        )
        child = make_acdc_node(
            said="CHILD_SAID",
            issuer="DIFFERENT_ISSUER",  # Does NOT match parent issuee
            issuee="LEAF_AID",
        )

        result = validate_i2i_edge(child, parent, "auth")
        assert result is not None
        assert result.operator == EdgeOperator.I2I
        assert result.edge_name == "auth"
        assert result.child_said == "CHILD_SAID"
        assert result.parent_said == "PARENT_SAID"
        assert "DIFFERENT_ISSUER" in result.constraint_violated
        assert "EXPECTED_ISSUER" in result.constraint_violated

    def test_i2i_skipped_for_bearer_parent(self):
        """I2I doesn't apply when parent is bearer credential (no issuee)."""
        parent = make_acdc_node(
            said="BEARER_PARENT",
            issuer="ROOT_AID",
            issuee=None,  # Bearer credential - no issuee
        )
        child = make_acdc_node(
            said="CHILD_SAID",
            issuer="ANY_ISSUER",
            issuee="LEAF_AID",
        )

        result = validate_i2i_edge(child, parent, "vetting")
        assert result is None  # Skipped, not violated


# =============================================================================
# DI2I Operator Tests
# =============================================================================


class TestDI2IValidation:
    """Tests for DI2I (Delegated-Issuer-to-Issuee) constraint validation."""

    def test_di2i_valid_when_direct_match(self):
        """DI2I passes when child.issuer == parent.issuee (like I2I)."""
        parent = make_acdc_node(
            said="PARENT_SAID",
            issuer="ROOT_AID",
            issuee="CHILD_ISSUER_AID",
        )
        child = make_acdc_node(
            said="CHILD_SAID",
            issuer="CHILD_ISSUER_AID",  # Direct match
        )

        result = validate_di2i_edge(child, parent, "auth", {})
        assert result is None

    def test_di2i_valid_when_delegation_chain_exists(self):
        """DI2I passes when delegation chain proves authority."""
        parent = make_acdc_node(
            said="PARENT_SAID",
            issuer="ROOT_AID",
            issuee="DELEGATOR_AID",  # Original authority holder
        )
        child = make_acdc_node(
            said="CHILD_SAID",
            issuer="DELEGATEE_AID",  # Different from parent issuee
        )
        # DE credential that proves delegation
        de_credential = make_acdc_node(
            said="DE_SAID",
            issuer="DELEGATOR_AID",
            issuee="DELEGATEE_AID",  # DE issuee = child issuer
            edges={"delegation": {"n": "PARENT_SAID"}},
            cred_type="DE",
        )

        # Include DE in dossier
        dossier_nodes = {
            "PARENT_SAID": parent,
            "CHILD_SAID": child,
            "DE_SAID": de_credential,
        }

        result = validate_di2i_edge(child, parent, "auth", dossier_nodes)
        assert result is None  # Delegation chain found

    def test_di2i_invalid_when_no_delegation_chain(self):
        """DI2I fails when no delegation chain exists."""
        parent = make_acdc_node(
            said="PARENT_SAID",
            issuer="ROOT_AID",
            issuee="DELEGATOR_AID",
        )
        child = make_acdc_node(
            said="CHILD_SAID",
            issuer="UNAUTHORIZED_AID",  # No delegation proof
        )

        result = validate_di2i_edge(child, parent, "auth", {})
        assert result is not None
        assert result.operator == EdgeOperator.DI2I
        assert "not delegated from" in result.constraint_violated


# =============================================================================
# NI2I Operator Tests
# =============================================================================


class TestNI2IValidation:
    """Tests for NI2I (Not-Issuer-to-Issuee) permissive validation."""

    def test_ni2i_always_passes(self):
        """NI2I has no constraint - always passes."""
        parent = make_acdc_node(
            said="PARENT_SAID",
            issuer="ROOT_AID",
            issuee="SOME_AID",
        )
        child = make_acdc_node(
            said="CHILD_SAID",
            issuer="COMPLETELY_DIFFERENT_AID",  # No relation to parent
        )

        result = validate_ni2i_edge(child, parent, "reference")
        assert result is None  # Always passes


# =============================================================================
# Operator Dispatch Tests
# =============================================================================


class TestOperatorDispatch:
    """Tests for validate_edge_operator dispatch function."""

    def test_dispatch_i2i_default(self):
        """Dispatch to I2I validation (default operator)."""
        parent = make_acdc_node(said="P", issuer="R", issuee="C")
        child = make_acdc_node(said="C", issuer="C")  # Valid I2I

        # Default operator (no 'o' field) is I2I
        edge_ref = {"n": "P"}
        result = validate_edge_operator(child, parent, "edge", edge_ref, {})
        assert result is None

    def test_dispatch_i2i_explicit(self):
        """Dispatch to I2I validation with explicit operator."""
        parent = make_acdc_node(said="P", issuer="R", issuee="C")
        child = make_acdc_node(said="C", issuer="C")  # Valid I2I

        edge_ref = {"n": "P", "o": "I2I"}
        result = validate_edge_operator(child, parent, "edge", edge_ref, {})
        assert result is None

    def test_dispatch_di2i(self):
        """Dispatch to DI2I validation."""
        parent = make_acdc_node(said="P", issuer="R", issuee="X")
        child = make_acdc_node(said="C", issuer="Y")  # No delegation

        edge_ref = {"n": "P", "o": "DI2I"}
        result = validate_edge_operator(child, parent, "edge", edge_ref, {})
        assert result is not None
        assert result.operator == EdgeOperator.DI2I

    def test_dispatch_ni2i(self):
        """Dispatch to NI2I validation (always passes)."""
        parent = make_acdc_node(said="P", issuer="R", issuee="X")
        child = make_acdc_node(said="C", issuer="Y")

        edge_ref = {"n": "P", "o": "NI2I"}
        result = validate_edge_operator(child, parent, "edge", edge_ref, {})
        assert result is None

    def test_dispatch_bare_said_defaults_to_i2i(self):
        """Bare SAID edge defaults to I2I operator."""
        parent = make_acdc_node(said="P", issuer="R", issuee="C")
        child = make_acdc_node(said="C", issuer="WRONG")  # Invalid I2I

        edge_ref = "P"  # Bare SAID string
        result = validate_edge_operator(child, parent, "edge", edge_ref, {})
        assert result is not None
        assert result.operator == EdgeOperator.I2I


# =============================================================================
# DAG-Wide Validation Tests
# =============================================================================


class TestValidateAllEdgeOperators:
    """Tests for validate_all_edge_operators on full DAGs."""

    def test_valid_chain_no_warnings(self):
        """Valid I2I chain produces no warnings."""
        root = make_acdc_node(said="ROOT", issuer="GLEIF", issuee="QVI_AID")
        middle = make_acdc_node(
            said="MIDDLE",
            issuer="QVI_AID",  # = root.issuee
            issuee="LE_AID",
            edges={"qvi": {"n": "ROOT"}},  # Default I2I
        )
        leaf = make_acdc_node(
            said="LEAF",
            issuer="LE_AID",  # = middle.issuee
            edges={"le": {"n": "MIDDLE"}},
        )

        dag = DossierDAG(
            nodes={
                "ROOT": root,
                "MIDDLE": middle,
                "LEAF": leaf,
            }
        )

        warnings = validate_all_edge_operators(dag)
        assert len(warnings) == 0

    def test_broken_chain_produces_warnings(self):
        """Broken I2I chain produces warnings."""
        root = make_acdc_node(said="ROOT", issuer="GLEIF", issuee="QVI_AID")
        leaf = make_acdc_node(
            said="LEAF",
            issuer="WRONG_AID",  # != root.issuee
            edges={"qvi": {"n": "ROOT"}},
        )

        dag = DossierDAG(nodes={"ROOT": root, "LEAF": leaf})

        warnings = validate_all_edge_operators(dag)
        assert len(warnings) == 1
        assert warnings[0].operator == EdgeOperator.I2I


# =============================================================================
# Edge Format Tests
# =============================================================================


class TestEdgeFormats:
    """Tests for different edge reference formats."""

    def test_edge_as_dict_with_n(self):
        """Edge as dict with 'n' key."""
        root = make_acdc_node(said="ROOT", issuer="R", issuee="C")
        child = make_acdc_node(
            said="CHILD",
            issuer="C",
            edges={"ref": {"n": "ROOT"}},
        )

        dag = DossierDAG(nodes={"ROOT": root, "CHILD": child})
        warnings = validate_all_edge_operators(dag)
        assert len(warnings) == 0

    def test_edge_as_dict_with_operator(self):
        """Edge as dict with explicit operator."""
        root = make_acdc_node(said="ROOT", issuer="R", issuee="X")
        child = make_acdc_node(
            said="CHILD",
            issuer="Y",  # Different from root.issuee
            edges={"ref": {"n": "ROOT", "o": "NI2I"}},  # Explicit NI2I
        )

        dag = DossierDAG(nodes={"ROOT": root, "CHILD": child})
        warnings = validate_all_edge_operators(dag)
        assert len(warnings) == 0  # NI2I = no constraint

    def test_edge_as_bare_said(self):
        """Edge as bare SAID string (defaults to I2I)."""
        root = make_acdc_node(said="ROOT", issuer="R", issuee="C")
        child = make_acdc_node(
            said="CHILD",
            issuer="C",
            edges={"ref": "ROOT"},  # Bare SAID, not dict
        )

        dag = DossierDAG(nodes={"ROOT": root, "CHILD": child})
        warnings = validate_all_edge_operators(dag)
        assert len(warnings) == 0


# =============================================================================
# Schema Constraint Tests
# =============================================================================


class TestSchemaConstraintValidation:
    """Tests for schema SAID constraint validation."""

    def test_schema_match_no_warning(self):
        """No warning when edge schema matches target."""
        target = make_acdc_node(said="TARGET", issuer="I", schema="SCHEMA_ABC")
        edge_ref = {"n": "TARGET", "s": "SCHEMA_ABC"}

        warning = validate_edge_schema(edge_ref, target, "qvi", "SOURCE_SAID")
        assert warning is None

    def test_schema_mismatch_produces_warning(self):
        """Warning when edge schema doesn't match target."""
        target = make_acdc_node(said="TARGET", issuer="I", schema="ACTUAL_SCHEMA")
        edge_ref = {"n": "TARGET", "s": "EXPECTED_SCHEMA"}

        warning = validate_edge_schema(edge_ref, target, "qvi", "SOURCE_SAID")
        assert warning is not None
        assert warning.code == ToIPWarningCode.EDGE_SCHEMA_MISMATCH
        assert "EXPECTED_SCHEMA" in warning.details
        assert "ACTUAL_SCHEMA" in warning.details

    def test_no_schema_constraint_no_warning(self):
        """No warning when edge has no schema constraint."""
        target = make_acdc_node(said="TARGET", issuer="I", schema="ANY_SCHEMA")
        edge_ref = {"n": "TARGET"}  # No 's' field

        warning = validate_edge_schema(edge_ref, target, "qvi", "SOURCE_SAID")
        assert warning is None


# =============================================================================
# Helper Function Tests
# =============================================================================


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_issuee_from_i_field(self):
        """Extract issuee from 'i' field."""
        attrs = {"i": "ISSUEE_AID"}
        assert _get_issuee_from_attributes(attrs) == "ISSUEE_AID"

    def test_get_issuee_from_issuee_field(self):
        """Extract issuee from 'issuee' field."""
        attrs = {"issuee": "ISSUEE_AID"}
        assert _get_issuee_from_attributes(attrs) == "ISSUEE_AID"

    def test_get_issuee_from_holder_field(self):
        """Extract issuee from 'holder' field."""
        attrs = {"holder": "HOLDER_AID"}
        assert _get_issuee_from_attributes(attrs) == "HOLDER_AID"

    def test_get_issuee_none_for_bearer(self):
        """Return None for bearer credential (no issuee)."""
        attrs = {"name": "Test", "value": 42}
        assert _get_issuee_from_attributes(attrs) is None

    def test_get_issuee_none_for_empty(self):
        """Return None for empty attributes."""
        assert _get_issuee_from_attributes({}) is None
        assert _get_issuee_from_attributes(None) is None
