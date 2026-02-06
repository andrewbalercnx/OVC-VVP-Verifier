# VVP Test Fixtures

Sprint 42: Comprehensive test assets for VVP signing and verification.

## Overview

This directory contains test fixtures for end-to-end VVP testing, including:

- **AIDs and Keys**: Test Ed25519 key pairs and KERI Autonomic Identifiers
- **Credentials**: Complete vLEI credential chain (GLEIF → QVI → LE → TN Allocation)
- **TN Mapping**: Configuration for test telephone number +441923311000
- **SIP Messages**: Pre-built SIP INVITE messages for various test scenarios
- **Logo**: Acme Corp test logo (SVG)

## Test Organization: Acme Corp

| Field | Value |
|-------|-------|
| **Name** | Acme Corp |
| **LEI** | 549300EXAMPLE000001 |
| **Pseudo-LEI** | 5493001234567890AB12 |
| **Test TN** | +441923311000 |
| **Extension** | 1001 |

## Credential Chain

```
GLEIF (Root of Trust)
│   AID: EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
│
└── QVI Credential
    │   SAID: EQviCredentialSAIDforTestingPurposesOnly000
    │   Issuer: GLEIF
    │   Issuee: Test QVI (EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk)
    │
    └── LE Credential (Acme Corp)
        │   SAID: ELeCredentialSAIDforAcmeCorpTestingOnly0000
        │   Issuer: Test QVI
        │   Issuee: Acme Corp (EHMnCf8_nIemuPx-cUHb_92fFXt9yjsn7NJJGKfgCkC0)
        │
        └── TN Allocation
            SAID: ETnAllocationSAIDforAcmeCorpExtension1001
            Numbers: +441923311000
            Channel: voice
```

## Files

| File | Description |
|------|-------------|
| `credentials.py` | AIDs, keys, credential builders, VVP header builders |
| `sip_messages.py` | Pre-built SIP INVITE messages for testing |
| `test_data.json` | All test data in JSON format |
| `acme_logo.svg` | Acme Corp test logo |

## Usage

### Python Tests

```python
from tests.fixtures import (
    ACME_CORP,
    TEST_TN,
    get_test_dossier,
    get_test_keys,
    create_test_vvp_identity,
    create_test_passport,
)

# Get test organization info
print(ACME_CORP["name"])  # "Acme Corp"

# Get the test telephone number
print(TEST_TN)  # "+441923311000"

# Get complete dossier with credentials
dossier = get_test_dossier()

# Get test keys
keys = get_test_keys("acme_signer")
print(keys["public"])  # Base64-encoded public key

# Create test VVP headers
vvp_identity = create_test_vvp_identity(orig_tn=TEST_TN)
passport = create_test_passport(orig_tn=TEST_TN)
```

### SIP Messages

```python
from tests.fixtures.sip_messages import (
    VALID_INVITE_EXT_1001,
    INVITE_NO_API_KEY,
    INVITE_INVALID_API_KEY,
    INVITE_UNMAPPED_TN,
    build_invite,
    build_many_invites,
)

# Use pre-built valid INVITE
response = await handle_invite(parse_sip_request(VALID_INVITE_EXT_1001))
assert response.status_code == 302

# Test missing API key
response = await handle_invite(parse_sip_request(INVITE_NO_API_KEY))
assert response.status_code == 401

# Build custom INVITE
custom_invite = build_invite(
    from_tn="+441234567890",
    to_tn="+442071234567",
    api_key="custom_api_key",
)

# Build many for rate limit testing
invites = build_many_invites(100)
```

### JSON Data

The `test_data.json` file can be loaded by external tools:

```bash
# Extract test TN
jq '.telephone_numbers.extension_1001.tn' test_data.json

# Get Acme Corp AID
jq '.aids.acme_corp.aid' test_data.json

# Get expected 302 response headers
jq '.expected_responses.successful_302.headers' test_data.json
```

## Test Scenarios

### 1. Successful Attestation (302)

- **INVITE**: From +441923311000 with valid API key
- **Expected**: 302 with VVP headers
- **Headers**: P-VVP-Identity, P-VVP-Passport, X-VVP-Brand-Name, X-VVP-Status: VALID

### 2. Missing API Key (401)

- **INVITE**: Any TN without X-VVP-API-Key header
- **Expected**: 401 Unauthorized
- **Headers**: X-VVP-Status: INVALID

### 3. Invalid API Key (401)

- **INVITE**: Any TN with incorrect API key
- **Expected**: 401 Unauthorized
- **Headers**: X-VVP-Status: INVALID

### 4. Unmapped TN (404)

- **INVITE**: From TN not in any mapping (e.g., +19999999999)
- **Expected**: 404 Not Found
- **Headers**: X-VVP-Status: INVALID

### 5. Rate Limited (403)

- **INVITE**: Many requests exceeding rate limit
- **Expected**: 403 Forbidden
- **Headers**: X-VVP-Status: INVALID

## Schema SAIDs

| Credential Type | Schema SAID |
|-----------------|-------------|
| QVI | EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao |
| Legal Entity | ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY |
| OOR Auth | EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E |
| OOR | EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy |
| TN Allocation | EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ |

## Warning

These test fixtures contain deterministic keys and credentials that are **NOT CRYPTOGRAPHICALLY SECURE**. They are intended only for testing purposes and must **NEVER** be used in production.
