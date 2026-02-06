"""Test credentials and keys for VVP signing/verification.

Sprint 42: Complete test credential chain for Acme Corp.

Credential Chain:
    GLEIF (Root)
      └── QVI Credential (Test QVI)
            └── LE Credential (Acme Corp)
                  └── TN Allocation (+441923311000)

All SAIDs, signatures, and keys are deterministic test values.
These should NOT be used in production.
"""

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Optional

# =============================================================================
# Test Organization
# =============================================================================

ACME_CORP = {
    "name": "Acme Corp",
    "lei": "549300EXAMPLE000001",  # Test LEI
    "pseudo_lei": "5493001234567890AB12",
    "address": {
        "street": "123 Test Street",
        "city": "London",
        "country": "GB",
    },
}

# Test telephone number for extension 1001
TEST_TN = "+441923311000"
TEST_TN_E164 = "+441923311000"

# =============================================================================
# Test AIDs (Autonomic Identifiers)
# =============================================================================

# GLEIF Root AID (simulates the real GLEIF root of trust)
GLEIF_AID = "EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4"

# Qualified vLEI Issuer AID (simulates a QVI like Provenant)
QVI_AID = "EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk"

# Acme Corp organization AID
ACME_CORP_AID = "EHMnCf8_nIemuPx-cUHb_92fFXt9yjsn7NJJGKfgCkC0"

# Acme Corp signer AID (person authorized to sign)
ACME_SIGNER_AID = "EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1"

# =============================================================================
# Test Keys (Ed25519)
# =============================================================================

# Pre-generated Ed25519 key pairs for testing
# These are deterministic test keys - DO NOT USE IN PRODUCTION

_TEST_KEYS = {
    "gleif": {
        "public": "aVMeRZLHvpVNHnfr9T9PZWLV6Xd5PXhzaKfOxKYjvQg=",
        "private": "qL2YKMPv5VYmKNfr9T9PZWLV6Xd5PXhzaKfOxKYjvQiaVMeRZLHvpVNHnfr9T9PZWLV6Xd5PXhzaKfOxKYjvQg=",
    },
    "qvi": {
        "public": "bWNeRZLHvpVNHnfr9T9PZWLV6Xd5PXhzaKfOxKYjvQg=",
        "private": "rM3YKMPv5VYmKNfr9T9PZWLV6Xd5PXhzaKfOxKYjvQibWNeRZLHvpVNHnfr9T9PZWLV6Xd5PXhzaKfOxKYjvQg=",
    },
    "acme_corp": {
        "public": "cXOeRZLHvpVNHnfr9T9PZWLV6Xd5PXhzaKfOxKYjvQg=",
        "private": "sN4YKMPv5VYmKNfr9T9PZWLV6Xd5PXhzaKfOxKYjvQicXOeRZLHvpVNHnfr9T9PZWLV6Xd5PXhzaKfOxKYjvQg=",
    },
    "acme_signer": {
        "public": "dYPeRZLHvpVNHnfr9T9PZWLV6Xd5PXhzaKfOxKYjvQg=",
        "private": "tO5YKMPv5VYmKNfr9T9PZWLV6Xd5PXhzaKfOxKYjvQidYPeRZLHvpVNHnfr9T9PZWLV6Xd5PXhzaKfOxKYjvQg=",
    },
}


def get_test_keys(identity: str) -> dict:
    """Get test keys for an identity.

    Args:
        identity: One of "gleif", "qvi", "acme_corp", "acme_signer"

    Returns:
        Dict with "public" and "private" base64-encoded keys
    """
    if identity not in _TEST_KEYS:
        raise ValueError(f"Unknown identity: {identity}")
    return _TEST_KEYS[identity]


# =============================================================================
# Schema SAIDs
# =============================================================================

# Official vLEI schema SAIDs
QVI_SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LE_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
OOR_AUTH_SCHEMA_SAID = "EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E"
OOR_SCHEMA_SAID = "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy"

# VVP-specific schema SAIDs
TN_ALLOCATION_SCHEMA_SAID = "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ"
TN_ALLOCATION_EXTENDED_SCHEMA_SAID = "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_"

# =============================================================================
# Test Credential SAIDs
# =============================================================================

# Pre-computed SAIDs for test credentials
QVI_CREDENTIAL_SAID = "EQviCredentialSAIDforTestingPurposesOnly000"
LE_CREDENTIAL_SAID = "ELeCredentialSAIDforAcmeCorpTestingOnly0000"
TN_ALLOCATION_SAID = "ETnAllocationSAIDforAcmeCorpExtension1001"

# =============================================================================
# Credential Builders
# =============================================================================


def get_qvi_credential() -> dict:
    """Get the test QVI credential (issued by GLEIF to QVI).

    Returns:
        ACDC credential dict
    """
    return {
        "v": "ACDC10JSON00011c_",
        "d": QVI_CREDENTIAL_SAID,
        "i": GLEIF_AID,  # Issuer is GLEIF
        "ri": "ETestRegistryForQVICredential000000000000",
        "s": QVI_SCHEMA_SAID,
        "a": {
            "d": "EQVIAttrBlockSAID0000000000000000000000",
            "i": QVI_AID,  # Issuee is the QVI
            "dt": "2024-01-01T00:00:00.000000+00:00",
            "LEI": "724500VKKSH9QOLTFR81",  # QVI's LEI
            "gracePeriod": 90,
        },
        "e": {},  # No edges for root credential
    }


def get_le_credential() -> dict:
    """Get the test Legal Entity credential (issued by QVI to Acme Corp).

    Returns:
        ACDC credential dict
    """
    return {
        "v": "ACDC10JSON00011c_",
        "d": LE_CREDENTIAL_SAID,
        "i": QVI_AID,  # Issuer is the QVI
        "ri": "ETestRegistryForLECredential0000000000000",
        "s": LE_SCHEMA_SAID,
        "a": {
            "d": "ELEAttrBlockSAID00000000000000000000000",
            "i": ACME_CORP_AID,  # Issuee is Acme Corp
            "dt": "2024-01-15T00:00:00.000000+00:00",
            "LEI": ACME_CORP["lei"],
            "personLegalName": ACME_CORP["name"],
            "officialRole": "Organization",
        },
        "e": {
            "d": "ELEEdgeBlockSAID0000000000000000000000",
            "qvi": {
                "n": QVI_CREDENTIAL_SAID,
                "s": QVI_SCHEMA_SAID,
            },
        },
    }


def get_tn_allocation_credential() -> dict:
    """Get the test TN Allocation credential (issued by QVI to Acme Corp).

    This credential proves Acme Corp owns the phone number +441923311000.

    Returns:
        ACDC credential dict
    """
    return {
        "v": "ACDC10JSON00011c_",
        "d": TN_ALLOCATION_SAID,
        "i": QVI_AID,  # Issuer is the QVI (or could be Acme Corp)
        "ri": "ETestRegistryForTNAllocation000000000000",
        "s": TN_ALLOCATION_SCHEMA_SAID,
        "a": {
            "d": "ETNAllocAttrBlockSAID000000000000000000",
            "i": ACME_CORP_AID,  # Issuee is Acme Corp
            "dt": "2024-02-01T00:00:00.000000+00:00",
            "numbers": {
                "tn": [TEST_TN],  # Single number allocation
            },
            "channel": "voice",
            "doNotOriginate": False,
        },
        "e": {
            "d": "ETNAllocEdgeBlockSAID0000000000000000000",
            "le": {
                "n": LE_CREDENTIAL_SAID,
                "s": LE_SCHEMA_SAID,
            },
        },
    }


def get_test_dossier() -> dict:
    """Get the complete test dossier for Acme Corp.

    The dossier contains the full credential chain:
    - QVI Credential (root of chain)
    - LE Credential (Legal Entity)
    - TN Allocation Credential (phone number ownership)

    Returns:
        Dossier dict with credentials array and metadata
    """
    return {
        "v": "VVP10JSON00001_",
        "d": "EDossierSAIDforAcmeCorpTestPurposes00000",
        "name": f"{ACME_CORP['name']} VVP Dossier",
        "root_said": TN_ALLOCATION_SAID,
        "credentials": [
            get_qvi_credential(),
            get_le_credential(),
            get_tn_allocation_credential(),
        ],
        "metadata": {
            "created_at": "2024-02-01T00:00:00.000000+00:00",
            "organization": ACME_CORP["name"],
            "tn": TEST_TN,
        },
    }


# =============================================================================
# VVP Header Builders
# =============================================================================


def create_test_vvp_identity(
    orig_tn: str = TEST_TN,
    dest_tn: str = "+442071234567",
    iat: Optional[int] = None,
) -> str:
    """Create a test VVP-Identity header.

    Args:
        orig_tn: Originating telephone number
        dest_tn: Destination telephone number
        iat: Issued-at timestamp (default: current time)

    Returns:
        Base64url-encoded VVP-Identity header
    """
    if iat is None:
        iat = int(time.time())

    identity = {
        "alg": "EdDSA",
        "typ": "vdp",
        "d": TN_ALLOCATION_SAID,  # Dossier root SAID
        "i": ACME_SIGNER_AID,  # Signer AID
        "iat": iat,
        "orig": {"tn": orig_tn},
        "dest": {"tn": dest_tn},
    }

    json_str = json.dumps(identity, separators=(",", ":"))
    return base64.urlsafe_b64encode(json_str.encode()).decode().rstrip("=")


def create_test_passport(
    orig_tn: str = TEST_TN,
    dest_tn: str = "+442071234567",
    iat: Optional[int] = None,
) -> str:
    """Create a test PASSporT JWT.

    Note: This creates a structurally valid but not cryptographically
    signed PASSporT for testing purposes.

    Args:
        orig_tn: Originating telephone number
        dest_tn: Destination telephone number
        iat: Issued-at timestamp (default: current time)

    Returns:
        JWT-formatted PASSporT string
    """
    if iat is None:
        iat = int(time.time())

    # JWT Header
    header = {
        "alg": "EdDSA",
        "typ": "passport",
        "ppt": "shaken",
        "x5u": f"https://cert.example.com/{ACME_SIGNER_AID}",
    }

    # JWT Payload (PASSporT claims)
    payload = {
        "attest": "A",  # Full attestation
        "dest": {"tn": [dest_tn.lstrip("+")]},
        "iat": iat,
        "orig": {"tn": orig_tn.lstrip("+")},
        "origid": "test-orig-id-12345",
    }

    # Encode header and payload
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).decode().rstrip("=")

    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode().rstrip("=")

    # Create test signature (not cryptographically valid)
    sig_input = f"{header_b64}.{payload_b64}"
    sig_bytes = hashlib.sha256(sig_input.encode()).digest()
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# =============================================================================
# TN Mapping
# =============================================================================

TEST_TN_MAPPING = {
    "id": "tn-mapping-acme-ext-1001",
    "tn": TEST_TN,
    "organization_id": "org-acme-corp-test",
    "organization_name": ACME_CORP["name"],
    "dossier_said": TN_ALLOCATION_SAID,
    "identity_name": "acme-signer",
    "brand_name": ACME_CORP["name"],
    "brand_logo_url": "https://example.com/acme-logo.svg",
    "enabled": True,
}


# =============================================================================
# API Key
# =============================================================================

TEST_API_KEY = "vvp_test_acme_corp_api_key_12345678901234567890"
TEST_API_KEY_PREFIX = "vvp_test"


# =============================================================================
# Deployed Service URLs
# =============================================================================

# SIP Signer service (deployed on PBX VM)
SIP_SIGNER_HOST = "pbx.rcnx.io"
SIP_SIGNER_PORT = 5060
SIP_SIGNER_TLS_PORT = 5061

# VVP Issuer service (Azure Container App)
VVP_ISSUER_URL = "https://vvp-issuer.rcnx.io"

# VVP Verifier service (Azure Container App)
VVP_VERIFIER_URL = "https://vvp-verifier.rcnx.io"

# Test dossier URL (served by issuer)
TEST_DOSSIER_URL = f"{VVP_ISSUER_URL}/dossiers/{TN_ALLOCATION_SAID}"


# =============================================================================
# VVP-Identity Header for Verifier (proper format)
# =============================================================================


def create_vvp_identity_header(
    evd_url: str = TEST_DOSSIER_URL,
    kid: str = ACME_SIGNER_AID,
    iat: Optional[int] = None,
    exp: Optional[int] = None,
    ppt: str = "shaken",
) -> str:
    """Create a VVP-Identity header in the format expected by the verifier.

    The verifier expects:
    - ppt: PASSporT profile type
    - kid: Key identifier (signer's AID)
    - evd: Evidence URL (where to fetch the dossier)
    - iat: Issued-at timestamp
    - exp: Expiry timestamp (optional)

    Args:
        evd_url: URL where the dossier can be fetched
        kid: Key identifier (signer AID)
        iat: Issued-at timestamp (default: current time)
        exp: Expiry timestamp (default: iat + 300)
        ppt: PASSporT profile type

    Returns:
        Base64url-encoded VVP-Identity header string
    """
    if iat is None:
        iat = int(time.time())
    if exp is None:
        exp = iat + 300

    identity = {
        "ppt": ppt,
        "kid": kid,
        "evd": evd_url,
        "iat": iat,
        "exp": exp,
    }

    json_str = json.dumps(identity, separators=(",", ":"))
    return base64.urlsafe_b64encode(json_str.encode()).decode().rstrip("=")


def get_dossier_credentials() -> list:
    """Get the dossier as a JSON array of ACDC credentials.

    This is the format expected when fetching from the evd URL.
    The verifier parses this array and builds a DAG from the credentials.

    Returns:
        List of ACDC credential dicts (ready to be JSON serialized)
    """
    return [
        # QVI Credential (root of chain - no incoming edges)
        {
            "d": QVI_CREDENTIAL_SAID,
            "i": GLEIF_AID,
            "s": QVI_SCHEMA_SAID,
            "a": {
                "d": "EQVIAttrBlockSAID0000000000000000000000",
                "i": QVI_AID,
                "dt": "2024-01-01T00:00:00.000000+00:00",
                "LEI": "724500VKKSH9QOLTFR81",
                "gracePeriod": 90,
            },
            "e": {},
        },
        # LE Credential (links to QVI via edge)
        {
            "d": LE_CREDENTIAL_SAID,
            "i": QVI_AID,
            "s": LE_SCHEMA_SAID,
            "a": {
                "d": "ELEAttrBlockSAID00000000000000000000000",
                "i": ACME_CORP_AID,
                "dt": "2024-01-15T00:00:00.000000+00:00",
                "LEI": ACME_CORP["lei"],
                "legalName": ACME_CORP["name"],
            },
            "e": {
                "d": "ELEEdgeBlockSAID0000000000000000000000",
                "qvi": {
                    "n": QVI_CREDENTIAL_SAID,
                    "s": QVI_SCHEMA_SAID,
                },
            },
        },
        # TN Allocation Credential (dossier root - links to LE via edge)
        {
            "d": TN_ALLOCATION_SAID,
            "i": QVI_AID,
            "s": TN_ALLOCATION_SCHEMA_SAID,
            "a": {
                "d": "ETNAllocAttrBlockSAID000000000000000000",
                "i": ACME_CORP_AID,
                "dt": "2024-02-01T00:00:00.000000+00:00",
                "numbers": {"tn": [TEST_TN]},
                "channel": "voice",
                "doNotOriginate": False,
            },
            "e": {
                "d": "ETNAllocEdgeBlockSAID0000000000000000000",
                "le": {
                    "n": LE_CREDENTIAL_SAID,
                    "s": LE_SCHEMA_SAID,
                },
            },
        },
    ]


def get_dossier_json() -> str:
    """Get the dossier as a JSON string.

    This is what should be served at the evd URL.

    Returns:
        JSON string of the dossier credentials array
    """
    return json.dumps(get_dossier_credentials(), indent=2)
