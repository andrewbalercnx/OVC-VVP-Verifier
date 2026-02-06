"""VVP Test Fixtures for Signing and Verification.

Sprint 42: Comprehensive test assets for end-to-end VVP testing.

This module provides:
- Test AIDs and Ed25519 key pairs
- Complete credential chain (GLEIF -> QVI -> LE -> TN Allocation)
- TN mapping for extension 1001 (+441923311000)
- Acme Corp organization identity
- Test logo asset

Usage:
    from tests.fixtures import (
        ACME_CORP,
        TEST_TN,
        get_test_dossier,
        get_test_keys,
    )
"""

from tests.fixtures.credentials import (
    # AIDs
    GLEIF_AID,
    QVI_AID,
    ACME_CORP_AID,
    ACME_SIGNER_AID,
    # Organization
    ACME_CORP,
    TEST_TN,
    TEST_TN_E164,
    TEST_API_KEY,
    # Service URLs
    SIP_SIGNER_HOST,
    SIP_SIGNER_PORT,
    SIP_SIGNER_TLS_PORT,
    VVP_ISSUER_URL,
    VVP_VERIFIER_URL,
    TEST_DOSSIER_URL,
    # Key functions
    get_test_keys,
    # Credential functions
    get_qvi_credential,
    get_le_credential,
    get_tn_allocation_credential,
    get_test_dossier,
    # Dossier for serving
    get_dossier_credentials,
    get_dossier_json,
    # VVP header functions
    create_test_vvp_identity,
    create_test_passport,
    create_vvp_identity_header,
)

__all__ = [
    # AIDs
    "GLEIF_AID",
    "QVI_AID",
    "ACME_CORP_AID",
    "ACME_SIGNER_AID",
    # Organization
    "ACME_CORP",
    "TEST_TN",
    "TEST_TN_E164",
    "TEST_API_KEY",
    # Service URLs
    "SIP_SIGNER_HOST",
    "SIP_SIGNER_PORT",
    "SIP_SIGNER_TLS_PORT",
    "VVP_ISSUER_URL",
    "VVP_VERIFIER_URL",
    "TEST_DOSSIER_URL",
    # Key functions
    "get_test_keys",
    # Credential functions
    "get_qvi_credential",
    "get_le_credential",
    "get_tn_allocation_credential",
    "get_test_dossier",
    # Dossier for serving
    "get_dossier_credentials",
    "get_dossier_json",
    # VVP header functions
    "create_test_vvp_identity",
    "create_test_passport",
    "create_vvp_identity_header",
]
