"""ACDC verification exceptions.

These exceptions map to existing ErrorCode values in api_models.py:
- ACDCSAIDMismatch -> ACDC_SAID_MISMATCH
- ACDCSignatureInvalid -> ACDC_PROOF_MISSING
- ACDCChainInvalid -> DOSSIER_GRAPH_INVALID
"""


class ACDCError(Exception):
    """Base exception for ACDC verification errors."""
    pass


class ACDCSAIDMismatch(ACDCError):
    """ACDC's self-addressing identifier doesn't match computed value.

    Maps to ErrorCode.ACDC_SAID_MISMATCH.
    """
    pass


class ACDCSignatureInvalid(ACDCError):
    """ACDC signature verification failed.

    Maps to ErrorCode.ACDC_PROOF_MISSING.
    """
    pass


class ACDCChainInvalid(ACDCError):
    """ACDC credential chain validation failed.

    This covers:
    - Edge target not found in dossier
    - Schema mismatch for credential type
    - Chain doesn't terminate at trusted root
    - Circular reference detected

    Maps to ErrorCode.DOSSIER_GRAPH_INVALID.
    """
    pass


class ACDCParseError(ACDCError):
    """Failed to parse ACDC structure.

    Maps to ErrorCode.DOSSIER_PARSE_FAILED.
    """
    pass
