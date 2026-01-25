"""Ed25519 signature verification for VVP PASSporTs.

Tier 1 implementation: Direct verification using public key embedded in KERI AID.
Tier 2 implementation: Resolve key state at reference time T via KEL lookup.

Note: pysodium is imported lazily inside functions to:
1. Avoid import errors when libsodium is not available at module load time
2. Enable testing of code paths that don't require signature verification
"""

from datetime import datetime, timezone
from typing import Optional

from app.vvp.passport import Passport
from .key_parser import parse_kid_to_verkey
from .exceptions import SignatureInvalidError


def verify_passport_signature(passport: Passport) -> None:
    """Verify PASSporT signature using Ed25519 (Tier 1).

    The signing input for JWT is: base64url(header).base64url(payload)
    The signature is verified against this input using the public key
    extracted from the kid field.

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature.

    Raises:
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID).
        ResolutionFailedError: Could not resolve/parse kid to key (→ INDETERMINATE).

    Note:
        Tier 1 does not validate key state at time T (iat).
        It assumes the key embedded in the AID is currently valid.
    """
    # Step 1: Parse kid to get verification key
    # This may raise ResolutionFailedError (recoverable → INDETERMINATE)
    verkey = parse_kid_to_verkey(passport.header.kid)

    # Step 2: Reconstruct JWT signing input: header.payload (ASCII bytes)
    # Per JWT spec, the signature covers the exact base64url-encoded strings
    signing_input = f"{passport.raw_header}.{passport.raw_payload}".encode("ascii")

    # Step 3: Verify signature using pysodium (libsodium)
    import pysodium
    try:
        # pysodium.crypto_sign_verify_detached raises ValueError if invalid
        pysodium.crypto_sign_verify_detached(
            passport.signature,
            signing_input,
            verkey.raw
        )
    except Exception:
        # Any verification failure is a cryptographic failure → INVALID
        raise SignatureInvalidError(
            f"Ed25519 signature verification failed for kid={passport.header.kid[:20]}..."
        )


async def verify_passport_signature_tier2(
    passport: Passport,
    reference_time: Optional[datetime] = None,
    oobi_url: Optional[str] = None,
    min_witnesses: Optional[int] = None,
    _allow_test_mode: bool = False
) -> None:
    """Verify PASSporT signature using historical key state (Tier 2).

    Resolves the key state at reference time T (default: passport iat),
    validates the KEL chain, and verifies the signature against the
    historical key state.

    Per spec §5A Step 4: "Resolve issuer key state at reference time T"

    WARNING: This function is TEST-ONLY. It does NOT support:
    - CESR binary format (rejects application/json+cesr responses)
    - KERI-compliant signature canonicalization (uses JSON sorted-keys)

    These limitations mean it cannot verify real KERI events from production
    witnesses. Enable TIER2_KEL_RESOLUTION_ENABLED only for testing with
    synthetic fixtures.

    Args:
        passport: Parsed Passport with raw_header, raw_payload, signature.
        reference_time: Reference time T (defaults to passport.payload.iat).
        oobi_url: Optional OOBI URL for fetching KEL.
        min_witnesses: Minimum witness receipts required.
        _allow_test_mode: Internal flag to bypass feature gate in tests.

    Raises:
        ResolutionFailedError: If TIER2_KEL_RESOLUTION_ENABLED is False.
        SignatureInvalidError: Signature cryptographically invalid (→ INVALID).
        KELChainInvalidError: KEL chain validation failed (→ INVALID).
        KeyNotYetValidError: No valid key state at reference time (→ INVALID).
        ResolutionFailedError: Could not resolve key state (→ INDETERMINATE).
    """
    from app.core.config import TIER2_KEL_RESOLUTION_ENABLED
    from .kel_resolver import resolve_key_state
    from .exceptions import ResolutionFailedError

    # Feature gate check
    if not TIER2_KEL_RESOLUTION_ENABLED and not _allow_test_mode:
        raise ResolutionFailedError(
            "Tier 2 KEL resolution is disabled. "
            "This feature is TEST-ONLY and does not support CESR format or "
            "KERI-compliant signature canonicalization. "
            "Set TIER2_KEL_RESOLUTION_ENABLED=True only for testing."
        )

    # Use iat as reference time if not specified
    # Use UTC to ensure consistent timezone handling
    if reference_time is None:
        reference_time = datetime.fromtimestamp(passport.payload.iat, tz=timezone.utc)

    # Resolve key state at reference time T
    # This may raise various exceptions that map to claim statuses
    key_state = await resolve_key_state(
        kid=passport.header.kid,
        reference_time=reference_time,
        oobi_url=oobi_url,
        min_witnesses=min_witnesses
    )

    # Reconstruct JWT signing input
    signing_input = f"{passport.raw_header}.{passport.raw_payload}".encode("ascii")

    # Verify signature against all signing keys from the resolved state
    # At least one key must validate the signature
    import pysodium
    signature_valid = False

    for signing_key in key_state.signing_keys:
        try:
            pysodium.crypto_sign_verify_detached(
                passport.signature,
                signing_input,
                signing_key
            )
            signature_valid = True
            break
        except Exception:
            continue

    if not signature_valid:
        raise SignatureInvalidError(
            f"Ed25519 signature verification failed for kid={passport.header.kid[:20]}... "
            f"at reference time {reference_time.isoformat()} "
            f"(key state seq={key_state.sequence})"
        )
