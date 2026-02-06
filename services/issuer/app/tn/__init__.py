"""TN Mapping Module for VVP Issuer.

Sprint 42: Maps telephone numbers to dossiers for SIP redirect signing.

This module provides:
- TNMappingStore: CRUD operations for TN-to-dossier mappings
- TN lookup with ownership validation against TN Allocation credentials
- Integration with SIP redirect service via /tn/lookup endpoint
"""

from app.tn.store import TNMappingStore
from app.tn.lookup import lookup_tn_with_validation, validate_tn_ownership

__all__ = [
    "TNMappingStore",
    "lookup_tn_with_validation",
    "validate_tn_ownership",
]
