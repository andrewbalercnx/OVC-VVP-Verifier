"""Tests for credential card view-model adapter.

Per Sprint 21 plan (PLAN_Credential_Card_UI.md), tests cover:
- Attribute mapping for each credential type
- Edge normalization (str, dict with n, dict with d, lists)
- Variant detection (compact/partial)
- Trusted root checking
- Missing data handling
"""

import pytest

from app.vvp.acdc.models import ACDC, ACDCChainResult
from app.vvp.ui.credential_viewmodel import (
    AttributeDisplay,
    CredentialCardViewModel,
    EdgeLink,
    IssuerInfo,
    RawACDCData,
    RevocationStatus,
    VariantLimitations,
    build_credential_card_vm,
    normalize_edge,
)


class TestNormalizeEdge:
    """Tests for edge normalization."""

    def test_normalize_edge_string(self):
        """String edge value returns the SAID directly."""
        result = normalize_edge("E" + "A" * 43)
        assert result == "E" + "A" * 43

    def test_normalize_edge_empty_string(self):
        """Empty string returns None."""
        result = normalize_edge("")
        assert result is None

    def test_normalize_edge_dict_with_n(self):
        """Dict with 'n' key extracts the node SAID."""
        result = normalize_edge({"n": "E" + "B" * 43, "s": "schema"})
        assert result == "E" + "B" * 43

    def test_normalize_edge_dict_with_d(self):
        """Dict with 'd' key extracts the digest SAID."""
        result = normalize_edge({"d": "E" + "C" * 43})
        assert result == "E" + "C" * 43

    def test_normalize_edge_dict_prefers_n_over_d(self):
        """Dict with both 'n' and 'd' prefers 'n'."""
        result = normalize_edge({"n": "E" + "N" * 43, "d": "E" + "D" * 43})
        assert result == "E" + "N" * 43

    def test_normalize_edge_list_returns_first_valid(self):
        """List of edges returns first valid SAID."""
        result = normalize_edge([
            None,
            "",
            {"n": "E" + "F" * 43},
        ])
        assert result == "E" + "F" * 43

    def test_normalize_edge_empty_list(self):
        """Empty list returns None."""
        result = normalize_edge([])
        assert result is None

    def test_normalize_edge_none(self):
        """None returns None."""
        result = normalize_edge(None)
        assert result is None

    def test_normalize_edge_invalid_type(self):
        """Invalid type (int, etc.) returns None."""
        result = normalize_edge(12345)
        assert result is None


class TestBuildCredentialCardVM:
    """Tests for the main view-model builder."""

    def _make_acdc(
        self,
        said: str = "E" + "A" * 43,
        issuer: str = "D" + "B" * 43,
        schema: str = "E" + "S" * 43,
        attributes: dict | str | None = None,
        edges: dict | None = None,
        variant: str = "full",
    ) -> ACDC:
        """Helper to create ACDC objects for testing."""
        return ACDC(
            version="ACDC10JSON00011c_",
            said=said,
            issuer_aid=issuer,
            schema_said=schema,
            attributes=attributes or {},
            edges=edges,
            variant=variant,
        )

    def test_basic_vm_fields(self):
        """Basic fields are correctly populated."""
        acdc = self._make_acdc()
        vm = build_credential_card_vm(acdc)

        assert vm.said == acdc.said
        assert vm.schema_said == acdc.schema_said
        assert vm.variant == "full"
        assert vm.status == "INDETERMINATE"  # No chain result

    def test_status_from_chain_result(self):
        """Status is taken from chain result when provided."""
        acdc = self._make_acdc()
        chain_result = ACDCChainResult(
            chain=[acdc],
            root_aid="some_root",
            validated=True,
            status="VALID",
        )

        vm = build_credential_card_vm(acdc, chain_result=chain_result)

        assert vm.status == "VALID"

    def test_revocation_from_result(self):
        """Revocation status is populated from revocation result."""
        acdc = self._make_acdc()
        revocation_result = {
            "status": "ACTIVE",
            "checked_at": "2024-01-01T00:00:00Z",
            "source": "witness",
            "error": None,
        }

        vm = build_credential_card_vm(acdc, revocation_result=revocation_result)

        assert vm.revocation.state == "ACTIVE"
        assert vm.revocation.checked_at == "2024-01-01T00:00:00Z"
        assert vm.revocation.source == "witness"
        assert vm.revocation.error is None

    def test_revocation_default(self):
        """Default revocation status is UNKNOWN."""
        acdc = self._make_acdc()
        vm = build_credential_card_vm(acdc)

        assert vm.revocation.state == "UNKNOWN"
        assert vm.revocation.source == "unknown"


class TestPrimaryAttribute:
    """Tests for primary attribute extraction."""

    def _make_acdc(self, cred_type_attrs: dict, edges: dict | None = None) -> ACDC:
        """Create ACDC with specific attributes for type detection."""
        return ACDC(
            version="ACDC10JSON00011c_",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes=cred_type_attrs,
            edges=edges,
            variant="full",
        )

    def test_ape_primary_from_tn(self):
        """APE credential with 'tn' is detected as TNAlloc by ACDC model.

        Note: The ACDC.credential_type property checks attributes before edges,
        so a credential with 'tn' attribute is classified as TNAlloc even if
        it has vetting edges. This is the expected behavior per the model.
        """
        acdc = self._make_acdc(
            {"tn": "+1-555-0100"},
            edges={"vetting": {"n": "E" + "V" * 43}},
        )
        vm = build_credential_card_vm(acdc)

        # Model detects as TNAlloc due to 'tn' attribute
        assert vm.credential_type == "TNAlloc"
        assert vm.primary.label == "Number Block"
        assert vm.primary.value == "+1-555-0100"

    def test_ape_without_tn_attribute(self):
        """APE credential detected via vetting edge when no tn attribute.

        APE credentials in production may have different attribute patterns.
        Detection falls back to edge-based when attributes don't match TNAlloc.
        """
        acdc = self._make_acdc(
            {"subject": "caller", "purpose": "authorization"},
            edges={"vetting": {"n": "E" + "V" * 43}},
        )
        vm = build_credential_card_vm(acdc)

        assert vm.credential_type == "APE"
        # No tn/phone attribute, so shows truncated SAID
        assert "E" in vm.primary.value

    def test_le_primary_from_legalname(self):
        """LE credential extracts legal name."""
        acdc = self._make_acdc({"legalName": "Acme Corporation", "LEI": "123456"})
        vm = build_credential_card_vm(acdc)

        assert vm.primary.label == "Legal Name"
        assert vm.primary.value == "Acme Corporation"

    def test_le_primary_fallback_to_lei(self):
        """LE credential falls back to LEI if no legalName."""
        acdc = self._make_acdc({"LEI": "549300EXAMPLE0LEI00"})
        vm = build_credential_card_vm(acdc)

        assert vm.primary.label == "LEI"
        assert vm.primary.value == "549300EXAMPLE0LEI00"

    def test_tnalloc_primary_from_tn(self):
        """TNAlloc credential extracts number block."""
        acdc = self._make_acdc(
            {"tn": ["+1-555-0000", "+1-555-9999"]},
            edges={"jl": {"n": "E" + "J" * 43}},
        )
        vm = build_credential_card_vm(acdc)

        # Should join multiple values
        assert "555-0000" in vm.primary.value
        assert "555-9999" in vm.primary.value

    def test_unknown_type_shows_said(self):
        """Unknown credential type shows truncated SAID."""
        acdc = self._make_acdc({})
        vm = build_credential_card_vm(acdc)

        assert "E" + "A" * 15 in vm.primary.value  # Truncated SAID


class TestSecondaryAttributes:
    """Tests for secondary attribute extraction."""

    def test_secondary_excludes_primary_field(self):
        """Secondary attributes don't include the primary field."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"legalName": "Acme Corp", "LEI": "123", "country": "US"},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        secondary_labels = [a.label for a in vm.secondary]
        # legalName is primary, should not be in secondary
        assert "Legalname" not in secondary_labels
        assert "Legal Name" not in secondary_labels

    def test_secondary_max_three(self):
        """Secondary attributes are limited to 3."""
        attrs = {f"field{i}": f"value{i}" for i in range(10)}
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes=attrs,
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert len(vm.secondary) <= 3

    def test_secondary_excludes_internal_fields(self):
        """Secondary attributes exclude d, dt, i, s, v, n and underscore fields."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"d": "x", "dt": "y", "_internal": "z", "visible": "show"},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        secondary_labels = [a.label.lower() for a in vm.secondary]
        assert "d" not in secondary_labels
        assert "dt" not in secondary_labels
        assert "_internal" not in secondary_labels


class TestEdgeBuilding:
    """Tests for edge link building."""

    def test_edges_with_availability(self):
        """Edge availability is determined by available_saids."""
        target_said = "E" + "T" * 43
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges={"vetting": {"n": target_said}},
            variant="full",
        )

        # With target in available set
        vm = build_credential_card_vm(acdc, available_saids={target_said})
        assert vm.edges["vetting"].available is True

        # Without target in available set
        vm = build_credential_card_vm(acdc, available_saids=set())
        assert vm.edges["vetting"].available is False

    def test_edge_labels_mapped(self):
        """Edge keys are mapped to human-readable labels."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges={
                "vetting": {"n": "E" + "1" * 43},
                "le": {"n": "E" + "2" * 43},
                "delegation": {"n": "E" + "3" * 43},
            },
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.edges["vetting"].label == "Vetted By"
        assert vm.edges["le"].label == "Legal Entity"
        assert vm.edges["delegation"].label == "Delegated By"


class TestVariantLimitations:
    """Tests for compact/partial variant detection."""

    def test_compact_variant_detected(self):
        """Compact variant (attributes is SAID string) is detected."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes="E" + "X" * 43,  # SAID reference, not dict
            edges=None,
            variant="compact",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.limitations.is_compact is True
        assert vm.limitations.has_variant_limitations is True

    def test_partial_variant_with_redacted_fields(self):
        """Partial variant with redacted fields is detected."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"name": "visible", "secret": "", "hidden": "#"},
            edges=None,
            variant="partial",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.limitations.is_partial is True
        assert "secret" in vm.limitations.redacted_fields
        assert "hidden" in vm.limitations.redacted_fields

    def test_partial_variant_with_underscore_placeholder(self):
        """Partial variant with '_' placeholder is detected."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={"name": "visible", "issuee": "_"},
            edges=None,
            variant="partial",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.limitations.is_partial is True
        assert "issuee" in vm.limitations.redacted_fields
        assert "name" not in vm.limitations.redacted_fields

    def test_partial_variant_with_typed_placeholder(self):
        """Partial variant with '_:type' placeholder is detected."""
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={
                "name": "visible",
                "date": "_:datetime",
                "amount": "_:number",
                "description": "_:string",
            },
            edges=None,
            variant="partial",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.limitations.is_partial is True
        assert "date" in vm.limitations.redacted_fields
        assert "amount" in vm.limitations.redacted_fields
        assert "description" in vm.limitations.redacted_fields
        assert "name" not in vm.limitations.redacted_fields

    def test_missing_edge_targets_tracked(self):
        """Missing edge targets are tracked in limitations."""
        target_said = "E" + "M" * 43
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges={"parent": {"n": target_said}},
            variant="full",
        )

        # Target not in available set
        vm = build_credential_card_vm(acdc, available_saids=set())

        assert target_said in vm.limitations.missing_edge_targets
        assert vm.limitations.has_variant_limitations is True


class TestIssuerInfo:
    """Tests for issuer information."""

    def test_issuer_aid_truncation(self):
        """Issuer AID is truncated for display."""
        long_aid = "D" + "X" * 43
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid=long_aid,
            schema_said="E" + "S" * 43,
            attributes={},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.issuer.aid == long_aid
        assert len(vm.issuer.aid_short) < len(long_aid)
        assert "..." in vm.issuer.aid_short

    def test_trusted_root_detection(self):
        """Trusted root status is determined from config."""
        # Use the actual GLEIF root from config
        from app.core.config import TRUSTED_ROOT_AIDS

        if TRUSTED_ROOT_AIDS:
            root_aid = next(iter(TRUSTED_ROOT_AIDS))
            acdc = ACDC(
                version="",
                said="E" + "A" * 43,
                issuer_aid=root_aid,
                schema_said="E" + "S" * 43,
                attributes={},
                edges=None,
                variant="full",
            )
            vm = build_credential_card_vm(acdc)
            assert vm.issuer.is_trusted_root is True

        # Non-root AID
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "N" * 43,  # Not a trusted root
            schema_said="E" + "S" * 43,
            attributes={},
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)
        assert vm.issuer.is_trusted_root is False


class TestRawData:
    """Tests for raw data preservation."""

    def test_raw_attributes_preserved(self):
        """Raw attributes are preserved for debug panel."""
        attrs = {"field1": "value1", "nested": {"a": 1}}
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes=attrs,
            edges=None,
            variant="full",
        )
        vm = build_credential_card_vm(acdc)

        assert vm.raw.attributes == attrs

    def test_source_format_detected(self):
        """Source format is detected from signature presence."""
        # With signature = CESR
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges=None,
            variant="full",
            signature=b"some_signature",
        )
        vm = build_credential_card_vm(acdc)
        assert vm.raw.source_format == "cesr"

        # Without signature = JSON
        acdc = ACDC(
            version="",
            said="E" + "A" * 43,
            issuer_aid="D" + "B" * 43,
            schema_said="E" + "S" * 43,
            attributes={},
            edges=None,
            variant="full",
            signature=None,
        )
        vm = build_credential_card_vm(acdc)
        assert vm.raw.source_format == "json"
