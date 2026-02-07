"""Shared KERI infrastructure for TEL revocation checking.

This package provides:
- TELClient: Lightweight TEL client for revocation status queries
- WitnessPool: Aggregated witness endpoints for AID resolution
- Data structures: CredentialStatus, ChainRevocationResult, etc.

Usage:
    from common.vvp.keri import (
        TELClient,
        get_tel_client,
        CredentialStatus,
        ChainRevocationResult,
        ChainExtractionResult,
        WitnessPool,
        get_witness_pool,
    )
"""

from .tel_client import (
    ChainExtractionResult,
    ChainRevocationResult,
    CredentialStatus,
    RevocationResult,
    TELClient,
    TELEvent,
    get_tel_client,
    reset_tel_client,
)
from .witness_pool import (
    WitnessEndpoint,
    WitnessPool,
    extract_witness_base_url,
    get_witness_pool,
    reset_witness_pool,
    validate_witness_url,
)

__all__ = [
    # TEL Client
    "TELClient",
    "get_tel_client",
    "reset_tel_client",
    "CredentialStatus",
    "TELEvent",
    "RevocationResult",
    "ChainExtractionResult",
    "ChainRevocationResult",
    # Witness Pool
    "WitnessPool",
    "get_witness_pool",
    "reset_witness_pool",
    "WitnessEndpoint",
    "validate_witness_url",
    "extract_witness_base_url",
]
