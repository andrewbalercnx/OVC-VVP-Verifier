"""Tests for authorization verification.

Per VVP §5A Steps 10-11:
- Step 10: Party authorization (Case A - no delegation)
- Step 11: TN rights validation

Sprint 15 implementation tests.
"""

import pytest

from app.vvp.acdc.models import ACDC
from app.vvp.api_models import ClaimStatus
from app.vvp.authorization import (
    AuthorizationClaimBuilder,
    AuthorizationContext,
    _find_credentials_by_type,
    _get_issuee,
    validate_authorization,
    verify_party_authorization,
    verify_tn_rights,
)


# =============================================================================
# Test Fixtures
# =============================================================================


def make_acdc(
    said: str,
    issuer_aid: str,
    attributes: dict = None,
    edges: dict = None,
    schema_said: str = "E" + "S" * 43,
) -> ACDC:
    """Create a minimal ACDC for testing."""
    return ACDC(
        version="ACDC10JSON00011c_",
        said=said,
        issuer_aid=issuer_aid,
        schema_said=schema_said,
        attributes=attributes,
        edges=edges,
        raw={},
    )


def make_ape_credential(said: str, issuer_aid: str, issuee_aid: str) -> ACDC:
    """Create an APE credential with vetting edge."""
    return make_acdc(
        said=said,
        issuer_aid=issuer_aid,
        attributes={"i": issuee_aid, "name": "Test APE"},
        edges={"vetting": {"n": "E" + "V" * 43}},  # Vetting edge makes it APE
    )


def make_de_credential(said: str, issuer_aid: str, delegate_aid: str) -> ACDC:
    """Create a DE credential with delegation edge."""
    return make_acdc(
        said=said,
        issuer_aid=issuer_aid,
        attributes={"i": delegate_aid, "name": "Test DE"},
        edges={"delegation": {"n": "E" + "D" * 43}},  # Delegation edge makes it DE
    )


def make_tnalloc_credential(
    said: str,
    issuer_aid: str,
    tn_allocation: str,
    issuee_aid: str = None,
) -> ACDC:
    """Create a TNAlloc credential with phone number allocation.

    Args:
        said: The SAID for this credential.
        issuer_aid: The issuer's AID.
        tn_allocation: The TN allocation (e.g., "+15551234567" or "+1555*").
        issuee_aid: The issuee's AID (holder of TN rights). Required for
            proper binding to accountable party per §5A Step 11.
    """
    attributes = {"tn": tn_allocation, "name": "Test TNAlloc"}
    if issuee_aid:
        attributes["i"] = issuee_aid
    return make_acdc(
        said=said,
        issuer_aid=issuer_aid,
        attributes=attributes,
    )


# =============================================================================
# Tests for _get_issuee
# =============================================================================


class TestGetIssuee:
    """Tests for issuee extraction from ACDC attributes."""

    def test_issuee_from_i_field(self):
        """Extract issuee from 'i' field."""
        acdc = make_acdc(
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            attributes={"i": "D" + "S" * 43},
        )
        assert _get_issuee(acdc) == "D" + "S" * 43

    def test_issuee_from_issuee_field(self):
        """Extract issuee from 'issuee' field."""
        acdc = make_acdc(
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            attributes={"issuee": "D" + "S" * 43},
        )
        assert _get_issuee(acdc) == "D" + "S" * 43

    def test_issuee_from_holder_field(self):
        """Extract issuee from 'holder' field."""
        acdc = make_acdc(
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            attributes={"holder": "D" + "S" * 43},
        )
        assert _get_issuee(acdc) == "D" + "S" * 43

    def test_issuee_missing_returns_none(self):
        """Missing issuee returns None."""
        acdc = make_acdc(
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            attributes={"name": "No issuee"},
        )
        assert _get_issuee(acdc) is None

    def test_issuee_no_attributes_returns_none(self):
        """No attributes returns None."""
        acdc = make_acdc(
            said="E" + "A" * 43,
            issuer_aid="D" + "I" * 43,
            attributes=None,
        )
        assert _get_issuee(acdc) is None


# =============================================================================
# Tests for _find_credentials_by_type
# =============================================================================


class TestFindCredentialsByType:
    """Tests for credential type filtering."""

    def test_find_ape_credentials(self):
        """Find APE credentials by type."""
        signer_aid = "D" + "S" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, signer_aid)
        tnalloc = make_tnalloc_credential("E" + "2" * 43, "D" + "I" * 43, "+15551234567")

        dossier_acdcs = {ape.said: ape, tnalloc.said: tnalloc}

        ape_creds = _find_credentials_by_type(dossier_acdcs, "APE")
        assert len(ape_creds) == 1
        assert ape_creds[0].said == ape.said

    def test_find_tnalloc_credentials(self):
        """Find TNAlloc credentials by type."""
        tnalloc = make_tnalloc_credential("E" + "1" * 43, "D" + "I" * 43, "+15551234567")

        dossier_acdcs = {tnalloc.said: tnalloc}

        tnalloc_creds = _find_credentials_by_type(dossier_acdcs, "TNAlloc")
        assert len(tnalloc_creds) == 1

    def test_find_de_credentials(self):
        """Find DE credentials by type."""
        de = make_de_credential("E" + "1" * 43, "D" + "I" * 43, "D" + "D" * 43)

        dossier_acdcs = {de.said: de}

        de_creds = _find_credentials_by_type(dossier_acdcs, "DE")
        assert len(de_creds) == 1

    def test_find_no_matching_type(self):
        """No credentials of requested type returns empty list."""
        tnalloc = make_tnalloc_credential("E" + "1" * 43, "D" + "I" * 43, "+15551234567")

        dossier_acdcs = {tnalloc.said: tnalloc}

        ape_creds = _find_credentials_by_type(dossier_acdcs, "APE")
        assert len(ape_creds) == 0


# =============================================================================
# Tests for verify_party_authorization
# =============================================================================


class TestVerifyPartyAuthorization:
    """Tests for party authorization (Step 10, Case A)."""

    def test_party_authorized_valid(self):
        """APE issuee matches signer AID -> VALID."""
        signer_aid = "D" + "S" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, signer_aid)
        tnalloc = make_tnalloc_credential("E" + "2" * 43, "D" + "I" * 43, "+15551234567")

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={ape.said: ape, tnalloc.said: tnalloc},
        )

        claim, matched_ape = verify_party_authorization(ctx)

        assert claim.status == ClaimStatus.VALID
        assert matched_ape is not None
        assert matched_ape.said == ape.said
        assert any("issuee_match" in ev for ev in claim.evidence)

    def test_party_authorized_no_ape(self):
        """No APE credential in dossier -> INVALID."""
        signer_aid = "D" + "S" * 43
        tnalloc = make_tnalloc_credential("E" + "1" * 43, "D" + "I" * 43, "+15551234567")

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={tnalloc.said: tnalloc},
        )

        claim, matched_ape = verify_party_authorization(ctx)

        assert claim.status == ClaimStatus.INVALID
        assert matched_ape is None
        assert any("No APE credential" in r for r in claim.reasons)

    def test_party_authorized_issuee_mismatch(self):
        """APE issuee doesn't match signer -> INVALID."""
        signer_aid = "D" + "S" * 43
        different_issuee = "D" + "X" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, different_issuee)

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={ape.said: ape},
        )

        claim, matched_ape = verify_party_authorization(ctx)

        assert claim.status == ClaimStatus.INVALID
        assert matched_ape is None
        assert any("No APE credential with issuee matching" in r for r in claim.reasons)

    def test_party_authorized_de_found_indeterminate(self):
        """DE credential found (Case B) -> INDETERMINATE."""
        signer_aid = "D" + "S" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, signer_aid)
        de = make_de_credential("E" + "2" * 43, "D" + "I" * 43, signer_aid)

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={ape.said: ape, de.said: de},
        )

        claim, matched_ape = verify_party_authorization(ctx)

        assert claim.status == ClaimStatus.INDETERMINATE
        assert matched_ape is None
        assert any("Delegation chain validation not yet implemented" in r for r in claim.reasons)

    def test_party_authorized_multiple_ape_one_matches(self):
        """Multiple APE credentials, one matches -> VALID."""
        signer_aid = "D" + "S" * 43
        ape1 = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, "D" + "X" * 43)  # No match
        ape2 = make_ape_credential("E" + "2" * 43, "D" + "I" * 43, signer_aid)  # Match

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={ape1.said: ape1, ape2.said: ape2},
        )

        claim, matched_ape = verify_party_authorization(ctx)

        assert claim.status == ClaimStatus.VALID
        assert matched_ape is not None
        assert matched_ape.said == ape2.said


# =============================================================================
# Tests for verify_tn_rights
# =============================================================================


class TestVerifyTnRights:
    """Tests for TN rights validation (Step 11).

    Per §5A Step 11, TN rights must be bound to the accountable party
    identified in Step 10. This means the TNAlloc credential must be
    issued to (issuee matches) the authorized party AID.
    """

    def test_tn_rights_valid_single_number(self):
        """Exact number match with bound issuee -> VALID."""
        signer_aid = "D" + "S" * 43
        tnalloc = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={tnalloc.said: tnalloc},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        assert claim.status == ClaimStatus.VALID
        assert any("covered:true" in ev for ev in claim.evidence)
        assert any("issuee_match" in ev for ev in claim.evidence)

    def test_tn_rights_valid_wildcard_coverage(self):
        """Number covered by wildcard (same digit count) with bound issuee -> VALID.

        Note: The current TNAlloc implementation pads wildcards to E.164 max
        (15 digits). For this test, we use a 15-digit number that falls within
        the wildcard range.
        """
        signer_aid = "D" + "S" * 43
        tnalloc = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+1555*", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+155512345678901",  # 15 digits, within +1555* range
            dossier_acdcs={tnalloc.said: tnalloc},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        assert claim.status == ClaimStatus.VALID

    def test_tn_rights_invalid_number_not_covered(self):
        """Number not covered by allocation -> INVALID."""
        signer_aid = "D" + "S" * 43
        tnalloc = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15559999999",  # Different number
            dossier_acdcs={tnalloc.said: tnalloc},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        assert claim.status == ClaimStatus.INVALID
        assert any("No TNAlloc credential for accountable party covers" in r for r in claim.reasons)

    def test_tn_rights_no_tnalloc_credential(self):
        """No TNAlloc credential in dossier -> INVALID."""
        signer_aid = "D" + "S" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, signer_aid)

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={ape.said: ape},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        assert claim.status == ClaimStatus.INVALID
        assert any("No TNAlloc credential found" in r for r in claim.reasons)

    def test_tn_rights_invalid_tn_format(self):
        """Invalid orig_tn format -> INVALID."""
        signer_aid = "D" + "S" * 43
        tnalloc = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="invalid-number",  # Not E.164
            dossier_acdcs={tnalloc.said: tnalloc},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        assert claim.status == ClaimStatus.INVALID
        assert any("Invalid orig.tn format" in r for r in claim.reasons)

    def test_tn_rights_multiple_tnalloc_coverage(self):
        """Number covered by one of multiple TNAlloc (both bound) -> VALID."""
        signer_aid = "D" + "S" * 43
        # Both TNAlloc credentials are bound to the same party
        tnalloc1 = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+14441234567", issuee_aid=signer_aid
        )
        tnalloc2 = make_tnalloc_credential(
            "E" + "2" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={tnalloc1.said: tnalloc1, tnalloc2.said: tnalloc2},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        assert claim.status == ClaimStatus.VALID

    def test_tn_rights_phone_field_alternative(self):
        """TNAlloc using 'phone' field instead of 'tn' -> VALID."""
        signer_aid = "D" + "S" * 43
        acdc = make_acdc(
            said="E" + "1" * 43,
            issuer_aid="D" + "I" * 43,
            attributes={"phone": "+15551234567", "i": signer_aid},  # Uses 'phone' field
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={acdc.said: acdc},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        assert claim.status == ClaimStatus.VALID

    def test_tn_rights_no_authorized_aid_indeterminate(self):
        """No authorized_aid provided -> INDETERMINATE."""
        signer_aid = "D" + "S" * 43
        tnalloc = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={tnalloc.said: tnalloc},
        )

        claim = verify_tn_rights(ctx, authorized_aid=None)

        assert claim.status == ClaimStatus.INDETERMINATE
        assert any("Cannot validate TN rights without accountable party AID" in r for r in claim.reasons)

    def test_tn_rights_issuee_mismatch_invalid(self):
        """TNAlloc issuee doesn't match authorized party -> INVALID.

        This is the key test for the binding requirement: even if a TNAlloc
        covers the orig.tn, it must be issued to the accountable party.
        """
        signer_aid = "D" + "S" * 43
        different_party = "D" + "X" * 43

        # TNAlloc is issued to a different party, not the signer
        tnalloc = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=different_party
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={tnalloc.said: tnalloc},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        assert claim.status == ClaimStatus.INVALID
        assert any("No TNAlloc credential issued to accountable party" in r for r in claim.reasons)

    def test_tn_rights_mixed_issuees_uses_correct_one(self):
        """Multiple TNAlloc with different issuees - only bound one considered.

        When multiple TNAlloc credentials exist but only one is bound to the
        accountable party, only that one should be used for TN coverage check.
        """
        signer_aid = "D" + "S" * 43
        other_party = "D" + "X" * 43

        # TNAlloc to other party covers the number
        tnalloc_other = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=other_party
        )
        # TNAlloc to signer covers a different number
        tnalloc_signer = make_tnalloc_credential(
            "E" + "2" * 43, "D" + "I" * 43, "+14441234567", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",  # Only covered by tnalloc_other, not bound to signer
            dossier_acdcs={tnalloc_other.said: tnalloc_other, tnalloc_signer.said: tnalloc_signer},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        # Should be INVALID because the TNAlloc covering orig.tn is not bound to signer
        assert claim.status == ClaimStatus.INVALID
        assert any("No TNAlloc credential for accountable party covers" in r for r in claim.reasons)

    def test_tn_rights_tnalloc_without_issuee_ignored(self):
        """TNAlloc without issuee field is not bound to any party.

        TNAlloc credentials that don't have an issuee field cannot satisfy
        the binding requirement and should be skipped.
        """
        signer_aid = "D" + "S" * 43

        # TNAlloc without issuee field
        tnalloc_no_issuee = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=None
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={tnalloc_no_issuee.said: tnalloc_no_issuee},
        )

        claim = verify_tn_rights(ctx, authorized_aid=signer_aid)

        # Should be INVALID because the TNAlloc has no issuee binding
        assert claim.status == ClaimStatus.INVALID
        assert any("No TNAlloc credential issued to accountable party" in r for r in claim.reasons)


# =============================================================================
# Tests for validate_authorization (Integration)
# =============================================================================


class TestValidateAuthorization:
    """Integration tests for full authorization validation.

    These tests verify the complete flow where:
    1. verify_party_authorization finds the accountable party (APE issuee)
    2. verify_tn_rights validates TN coverage bound to that party
    """

    def test_authorization_both_valid(self):
        """Both party and TN rights valid -> both VALID.

        APE issuee matches signer, TNAlloc issuee matches signer, TN covered.
        """
        signer_aid = "D" + "S" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, signer_aid)
        # TNAlloc must be issued to the same party as the APE issuee
        tnalloc = make_tnalloc_credential(
            "E" + "2" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={ape.said: ape, tnalloc.said: tnalloc},
        )

        party_claim, tn_claim = validate_authorization(ctx)

        assert party_claim.status == ClaimStatus.VALID
        assert tn_claim.status == ClaimStatus.VALID

    def test_authorization_party_invalid_tn_indeterminate(self):
        """Party invalid -> TN rights INDETERMINATE (no accountable party).

        When party authorization fails, we don't have an accountable party AID
        to bind TN rights to, so tn_rights_valid becomes INDETERMINATE.
        """
        signer_aid = "D" + "S" * 43
        different_issuee = "D" + "X" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, different_issuee)  # Wrong issuee
        # TNAlloc is bound to the different party (APE issuee), not the signer
        tnalloc = make_tnalloc_credential(
            "E" + "2" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=different_issuee
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={ape.said: ape, tnalloc.said: tnalloc},
        )

        party_claim, tn_claim = validate_authorization(ctx)

        assert party_claim.status == ClaimStatus.INVALID
        # No matching APE means no authorized_aid, so TN rights is INDETERMINATE
        assert tn_claim.status == ClaimStatus.INDETERMINATE

    def test_authorization_party_valid_tn_invalid_wrong_number(self):
        """Party valid, TN not covered -> TN rights INVALID."""
        signer_aid = "D" + "S" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, signer_aid)
        # TNAlloc is bound to signer but covers different number
        tnalloc = make_tnalloc_credential(
            "E" + "2" * 43, "D" + "I" * 43, "+14441234567", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",  # Not covered by TNAlloc
            dossier_acdcs={ape.said: ape, tnalloc.said: tnalloc},
        )

        party_claim, tn_claim = validate_authorization(ctx)

        assert party_claim.status == ClaimStatus.VALID
        assert tn_claim.status == ClaimStatus.INVALID

    def test_authorization_party_valid_tn_invalid_wrong_issuee(self):
        """Party valid, TNAlloc not bound to accountable party -> INVALID.

        This is the critical binding test: even if a TNAlloc covers the TN,
        if it's not issued to the accountable party, TN rights is INVALID.
        """
        signer_aid = "D" + "S" * 43
        other_party = "D" + "X" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, signer_aid)
        # TNAlloc covers the number but is issued to someone else
        tnalloc = make_tnalloc_credential(
            "E" + "2" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=other_party
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={ape.said: ape, tnalloc.said: tnalloc},
        )

        party_claim, tn_claim = validate_authorization(ctx)

        assert party_claim.status == ClaimStatus.VALID
        assert tn_claim.status == ClaimStatus.INVALID
        assert any("No TNAlloc credential issued to accountable party" in r for r in tn_claim.reasons)

    def test_authorization_both_invalid_no_ape(self):
        """No APE -> party INVALID, TN rights INDETERMINATE."""
        signer_aid = "D" + "S" * 43
        tnalloc = make_tnalloc_credential(
            "E" + "1" * 43, "D" + "I" * 43, "+15551234567", issuee_aid=signer_aid
        )

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={tnalloc.said: tnalloc},  # No APE
        )

        party_claim, tn_claim = validate_authorization(ctx)

        assert party_claim.status == ClaimStatus.INVALID
        # No APE means no authorized_aid, so TN rights is INDETERMINATE
        assert tn_claim.status == ClaimStatus.INDETERMINATE

    def test_authorization_no_tnalloc_at_all(self):
        """Party valid, no TNAlloc in dossier -> TN rights INVALID."""
        signer_aid = "D" + "S" * 43
        ape = make_ape_credential("E" + "1" * 43, "D" + "I" * 43, signer_aid)

        ctx = AuthorizationContext(
            pss_signer_aid=signer_aid,
            orig_tn="+15551234567",
            dossier_acdcs={ape.said: ape},  # No TNAlloc
        )

        party_claim, tn_claim = validate_authorization(ctx)

        assert party_claim.status == ClaimStatus.VALID
        assert tn_claim.status == ClaimStatus.INVALID
        assert any("No TNAlloc credential found" in r for r in tn_claim.reasons)


# =============================================================================
# Tests for AuthorizationClaimBuilder
# =============================================================================


class TestAuthorizationClaimBuilder:
    """Tests for the claim builder utility."""

    def test_claim_builder_initial_state(self):
        """New claim builder starts VALID with empty reasons/evidence."""
        claim = AuthorizationClaimBuilder("test_claim")
        assert claim.status == ClaimStatus.VALID
        assert claim.reasons == []
        assert claim.evidence == []

    def test_claim_builder_fail_invalid(self):
        """Fail with INVALID sets status to INVALID."""
        claim = AuthorizationClaimBuilder("test_claim")
        claim.fail(ClaimStatus.INVALID, "Test failure")
        assert claim.status == ClaimStatus.INVALID
        assert "Test failure" in claim.reasons

    def test_claim_builder_fail_indeterminate(self):
        """Fail with INDETERMINATE sets status to INDETERMINATE."""
        claim = AuthorizationClaimBuilder("test_claim")
        claim.fail(ClaimStatus.INDETERMINATE, "Test indeterminate")
        assert claim.status == ClaimStatus.INDETERMINATE
        assert "Test indeterminate" in claim.reasons

    def test_claim_builder_invalid_wins_over_indeterminate(self):
        """INVALID status takes precedence over INDETERMINATE."""
        claim = AuthorizationClaimBuilder("test_claim")
        claim.fail(ClaimStatus.INDETERMINATE, "First")
        claim.fail(ClaimStatus.INVALID, "Second")
        assert claim.status == ClaimStatus.INVALID

    def test_claim_builder_add_evidence(self):
        """Evidence can be accumulated."""
        claim = AuthorizationClaimBuilder("test_claim")
        claim.add_evidence("ev1")
        claim.add_evidence("ev2")
        assert claim.evidence == ["ev1", "ev2"]
