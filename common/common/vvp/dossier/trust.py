"""Trust decision based on revocation status.

Implements the VVP trust model:
- Unknown revocation status → TRUSTED (allow call to proceed)
- Revoked → UNTRUSTED (reject signing)

This is a deliberate policy choice for call flow continuity. The first
signing attempt proceeds with UNKNOWN (trusted) status while background
revocation check runs. Subsequent calls use the cached result.
"""

from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from common.vvp.keri.tel_client import ChainRevocationResult


class TrustDecision(str, Enum):
    """Trust decision based on revocation status."""

    TRUSTED = "TRUSTED"  # Allow signing/verification
    UNTRUSTED = "UNTRUSTED"  # Reject (revoked credential)


def revocation_to_trust(
    chain_revocation: Optional["ChainRevocationResult"],
    unknown_is_trusted: bool = True,
) -> TrustDecision:
    """Convert revocation result to trust decision.

    Per VVP policy requirements:
    - REVOKED -> UNTRUSTED (credential chain is invalid)
    - ACTIVE -> TRUSTED (all credentials valid)
    - UNKNOWN/ERROR/None -> TRUSTED if unknown_is_trusted (default)

    Args:
        chain_revocation: Result from TEL revocation check.
        unknown_is_trusted: Whether unknown status means trusted.
            Default True per VVP policy for call flow continuity.

    Returns:
        TrustDecision enum value.
    """
    if chain_revocation is None:
        return TrustDecision.TRUSTED if unknown_is_trusted else TrustDecision.UNTRUSTED

    # Import here to avoid circular dependency
    from common.vvp.keri.tel_client import CredentialStatus

    if chain_revocation.chain_status == CredentialStatus.REVOKED:
        return TrustDecision.UNTRUSTED

    if chain_revocation.chain_status == CredentialStatus.ACTIVE:
        return TrustDecision.TRUSTED

    # UNKNOWN or ERROR
    return TrustDecision.TRUSTED if unknown_is_trusted else TrustDecision.UNTRUSTED
