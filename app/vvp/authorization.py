"""Authorization verification for VVP Verifier.

Per VVP Specification §5A Steps 10-11:
- Step 10: Verify originating party is authorized to sign PASSporT
- Step 11: Verify accountable party has TN rights for orig.tn

Sprint 15 implements Case A (no delegation). Case B (delegation chains)
returns INDETERMINATE and is deferred to a future sprint.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from app.vvp.acdc.models import ACDC
from app.vvp.api_models import ClaimStatus
from app.vvp.tn_utils import TNParseError, is_subset, parse_tn_allocation


@dataclass
class AuthorizationContext:
    """Context for authorization validation.

    Attributes:
        pss_signer_aid: AID extracted from PASSporT kid header.
        orig_tn: E.164 telephone number from passport.payload.orig["tn"].
        dossier_acdcs: All ACDC credentials parsed from the dossier.
    """
    pss_signer_aid: str
    orig_tn: str
    dossier_acdcs: Dict[str, ACDC]


@dataclass
class AuthorizationClaimBuilder:
    """Builder for accumulating claim evidence and status.

    Note: This is a local copy to avoid circular imports with verify.py.
    The interface matches verify.py ClaimBuilder for compatibility.
    verify.py will convert these to proper ClaimNode objects.
    """
    name: str
    status: ClaimStatus = ClaimStatus.VALID
    reasons: List[str] = None
    evidence: List[str] = None

    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []
        if self.evidence is None:
            self.evidence = []

    def fail(self, status: ClaimStatus, reason: str) -> None:
        """Record a failure with status and reason."""
        if status == ClaimStatus.INVALID:
            self.status = ClaimStatus.INVALID
        elif status == ClaimStatus.INDETERMINATE and self.status == ClaimStatus.VALID:
            self.status = ClaimStatus.INDETERMINATE
        self.reasons.append(reason)

    def add_evidence(self, ev: str) -> None:
        """Add evidence string."""
        self.evidence.append(ev)


def _get_issuee(acdc: ACDC) -> Optional[str]:
    """Extract issuee AID from ACDC attributes.

    Per ACDC spec, the issuee may be in 'i', 'issuee', or 'holder' field.

    Args:
        acdc: The ACDC credential.

    Returns:
        The issuee AID string, or None if not found.
    """
    if not acdc.attributes:
        return None
    return (
        acdc.attributes.get("i") or
        acdc.attributes.get("issuee") or
        acdc.attributes.get("holder")
    )


def _find_credentials_by_type(
    dossier_acdcs: Dict[str, ACDC],
    cred_type: str
) -> List[ACDC]:
    """Find all credentials of a specific type in the dossier.

    Args:
        dossier_acdcs: All credentials from dossier.
        cred_type: Credential type to find (e.g., "APE", "DE", "TNAlloc").

    Returns:
        List of matching credentials.
    """
    return [acdc for acdc in dossier_acdcs.values() if acdc.credential_type == cred_type]


def verify_party_authorization(
    ctx: AuthorizationContext,
) -> Tuple[AuthorizationClaimBuilder, Optional[ACDC]]:
    """Verify originating party is authorized to sign PASSporT (Step 10).

    Per §5A Step 10, Case A (no delegation):
    - Find APE credential where issuee == pss_signer_aid
    - This proves OP is the accountable party and authorized to sign

    Case B (delegation) is detected but deferred - returns INDETERMINATE.

    Args:
        ctx: Authorization context with signer AID and dossier credentials.

    Returns:
        Tuple of (AuthorizationClaimBuilder for party_authorized, matching APE if found).
    """
    claim = AuthorizationClaimBuilder("party_authorized")

    # Find APE and DE credentials
    ape_credentials = _find_credentials_by_type(ctx.dossier_acdcs, "APE")
    de_credentials = _find_credentials_by_type(ctx.dossier_acdcs, "DE")

    # Check for Case B (delegation) - defer to future sprint
    if de_credentials:
        claim.fail(
            ClaimStatus.INDETERMINATE,
            "Delegation chain validation not yet implemented (Case B deferred)"
        )
        claim.add_evidence(f"de_count:{len(de_credentials)}")
        return claim, None

    # Case A: No delegation - OP must be issuee of APE
    if not ape_credentials:
        claim.fail(
            ClaimStatus.INVALID,
            "No APE credential found in dossier"
        )
        return claim, None

    # Check if any APE has issuee matching the signer
    for ape in ape_credentials:
        issuee = _get_issuee(ape)
        if issuee == ctx.pss_signer_aid:
            claim.add_evidence(f"ape_said:{ape.said[:16]}...")
            claim.add_evidence(f"issuee_match:{ctx.pss_signer_aid[:16]}...")
            return claim, ape

    # No matching APE found
    claim.fail(
        ClaimStatus.INVALID,
        f"No APE credential with issuee matching signer AID {ctx.pss_signer_aid[:20]}..."
    )
    claim.add_evidence(f"ape_count:{len(ape_credentials)}")
    claim.add_evidence(f"signer:{ctx.pss_signer_aid[:16]}...")

    return claim, None


def verify_tn_rights(
    ctx: AuthorizationContext,
    authorized_aid: Optional[str] = None,
) -> AuthorizationClaimBuilder:
    """Verify accountable party has TN rights for orig.tn (Step 11).

    Per §5A Step 11:
    - Find TNAlloc credential(s) in dossier
    - Verify the TNAlloc is bound to the accountable party (authorized_aid)
    - Verify orig.tn is covered by the TNAlloc allocation

    Args:
        ctx: Authorization context with orig_tn and dossier credentials.
        authorized_aid: The AID of the accountable party from Step 10 (APE issuee).
            If None, TN rights cannot be validated and returns INDETERMINATE.

    Returns:
        AuthorizationClaimBuilder for tn_rights_valid claim.
    """
    claim = AuthorizationClaimBuilder("tn_rights_valid")

    # If no authorized_aid, we cannot bind TN rights to accountable party
    if not authorized_aid:
        claim.fail(
            ClaimStatus.INDETERMINATE,
            "Cannot validate TN rights without accountable party AID"
        )
        return claim

    # Find TNAlloc credentials
    tnalloc_credentials = _find_credentials_by_type(ctx.dossier_acdcs, "TNAlloc")

    if not tnalloc_credentials:
        claim.fail(
            ClaimStatus.INVALID,
            "No TNAlloc credential found in dossier"
        )
        return claim

    # Parse the orig_tn as a range (single number)
    try:
        orig_ranges = parse_tn_allocation(ctx.orig_tn)
    except TNParseError as e:
        claim.fail(
            ClaimStatus.INVALID,
            f"Invalid orig.tn format: {e}"
        )
        return claim

    # Filter to TNAlloc credentials bound to the accountable party
    bound_tnallocs = []
    for tnalloc in tnalloc_credentials:
        issuee = _get_issuee(tnalloc)
        if issuee == authorized_aid:
            bound_tnallocs.append(tnalloc)

    if not bound_tnallocs:
        claim.fail(
            ClaimStatus.INVALID,
            f"No TNAlloc credential issued to accountable party {authorized_aid[:20]}..."
        )
        claim.add_evidence(f"tnalloc_count:{len(tnalloc_credentials)}")
        claim.add_evidence(f"authorized_aid:{authorized_aid[:16]}...")
        return claim

    # Check if any bound TNAlloc covers the orig_tn
    for tnalloc in bound_tnallocs:
        # Extract TN allocation from attributes
        tn_data = (
            tnalloc.attributes.get("tn") if tnalloc.attributes else None
        ) or (
            tnalloc.attributes.get("phone") if tnalloc.attributes else None
        ) or (
            tnalloc.attributes.get("allocation") if tnalloc.attributes else None
        )

        if not tn_data:
            continue  # Skip credentials without TN data

        try:
            alloc_ranges = parse_tn_allocation(tn_data)
        except TNParseError:
            continue  # Skip malformed allocations

        # Check if orig_tn is covered by this allocation
        if is_subset(orig_ranges, alloc_ranges):
            claim.add_evidence(f"tnalloc_said:{tnalloc.said[:16]}...")
            claim.add_evidence(f"issuee_match:{authorized_aid[:16]}...")
            claim.add_evidence(f"orig_tn:{ctx.orig_tn}")
            claim.add_evidence(f"covered:true")
            return claim

    # No bound TNAlloc covers the orig_tn
    claim.fail(
        ClaimStatus.INVALID,
        f"No TNAlloc credential for accountable party covers orig.tn {ctx.orig_tn}"
    )
    claim.add_evidence(f"bound_tnalloc_count:{len(bound_tnallocs)}")
    claim.add_evidence(f"authorized_aid:{authorized_aid[:16]}...")
    claim.add_evidence(f"orig_tn:{ctx.orig_tn}")

    return claim


def validate_authorization(
    ctx: AuthorizationContext,
) -> Tuple[AuthorizationClaimBuilder, AuthorizationClaimBuilder]:
    """Main entry point: validate party authorization and TN rights.

    Orchestrates §5A Steps 10-11:
    1. verify_party_authorization (Step 10) - identifies accountable party
    2. verify_tn_rights (Step 11) - validates TN rights for accountable party

    Per §5A Step 11, TN rights must be validated for the accountable party
    identified in Step 10, not just any party in the dossier.

    Args:
        ctx: Authorization context with all required data.

    Returns:
        Tuple of (party_authorized claim, tn_rights_valid claim).
    """
    party_claim, matching_ape = verify_party_authorization(ctx)

    # Extract authorized AID from matching APE credential for TN rights binding
    # In Case A, the accountable party is the APE issuee (== signer)
    authorized_aid = None
    if matching_ape is not None:
        authorized_aid = _get_issuee(matching_ape)

    tn_rights_claim = verify_tn_rights(ctx, authorized_aid=authorized_aid)

    return party_claim, tn_rights_claim
