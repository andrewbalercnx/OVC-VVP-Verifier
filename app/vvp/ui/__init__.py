"""VVP UI utilities.

This module provides view-model adapters and helpers for rendering
ACDC credentials in the web UI. The view-model pattern decouples
raw ACDC data structures from template rendering, enabling:

- Normalized attribute access across schema variations
- Graceful handling of compact/partial credential variants
- Separation of ClaimStatus from revocation state
"""

from app.vvp.ui.credential_viewmodel import (
    AttributeDisplay,
    AttributeSection,
    CredentialCardViewModel,
    EdgeLink,
    IssuerIdentity,
    IssuerInfo,
    RawACDCData,
    RevocationStatus,
    VariantLimitations,
    VCardInfo,
    build_credential_card_vm,
    build_issuer_identity_map,
    build_issuer_identity_map_async,
    normalize_edge,
)

__all__ = [
    "AttributeDisplay",
    "AttributeSection",
    "CredentialCardViewModel",
    "EdgeLink",
    "IssuerIdentity",
    "IssuerInfo",
    "RawACDCData",
    "RevocationStatus",
    "VariantLimitations",
    "VCardInfo",
    "build_credential_card_vm",
    "build_issuer_identity_map",
    "build_issuer_identity_map_async",
    "normalize_edge",
]
