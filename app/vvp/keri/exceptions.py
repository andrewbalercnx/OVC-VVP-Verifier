"""KERI-specific exceptions mapped to VVP error codes.

Per spec §5.4:
- Cryptographic failures → INVALID (non-recoverable)
- Resolution failures → INDETERMINATE (recoverable)
"""

from app.vvp.api_models import ErrorCode


class KeriError(Exception):
    """Base exception for KERI operations.

    Carries an error code that maps to ErrorCode constants per §4.2A.
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class SignatureInvalidError(KeriError):
    """Signature is cryptographically invalid.

    Maps to PASSPORT_SIG_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "Signature verification failed"):
        super().__init__(ErrorCode.PASSPORT_SIG_INVALID, message)


class ResolutionFailedError(KeriError):
    """Transient failure resolving key state.

    Maps to KERI_RESOLUTION_FAILED (recoverable → INDETERMINATE).
    Used when:
    - kid format is unrecognized
    - kid algorithm is not supported
    - Network/fetch failures (Tier 2)
    """

    def __init__(self, message: str = "KERI resolution failed"):
        super().__init__(ErrorCode.KERI_RESOLUTION_FAILED, message)


class StateInvalidError(KeriError):
    """Key state is cryptographically invalid.

    Maps to KERI_STATE_INVALID (non-recoverable → INVALID).
    Reserved for Tier 2 when KEL validation fails.
    """

    def __init__(self, message: str = "KERI state invalid"):
        super().__init__(ErrorCode.KERI_STATE_INVALID, message)


class KELChainInvalidError(StateInvalidError):
    """KEL chain validation failed.

    Used when:
    - Chain continuity broken (prior_digest doesn't match previous event's digest)
    - Event signature is invalid (not signed by keys from prior event)
    - Inception event is not properly self-signed

    Maps to KERI_STATE_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "KEL chain validation failed"):
        super().__init__(message)


class KeyNotYetValidError(StateInvalidError):
    """No establishment event exists at or before reference time T.

    This occurs when the reference time (PASSporT iat) is before the
    AID's inception event, meaning no valid key state existed at that time.

    Maps to KERI_STATE_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "No valid key state at reference time"):
        super().__init__(message)


class DelegationNotSupportedError(ResolutionFailedError):
    """Delegated event (dip/drt) detected but not yet supported.

    Delegated identifiers require additional validation of the delegator's
    authorization, which is deferred to a future phase.

    Maps to KERI_RESOLUTION_FAILED (recoverable → INDETERMINATE).
    """

    def __init__(self, message: str = "Delegated events not yet supported"):
        super().__init__(message)


class OOBIContentInvalidError(KeriError):
    """OOBI response has invalid content type or malformed data.

    Maps to VVP_OOBI_CONTENT_INVALID (non-recoverable → INVALID).
    """

    def __init__(self, message: str = "Invalid OOBI content"):
        super().__init__(ErrorCode.VVP_OOBI_CONTENT_INVALID, message)
