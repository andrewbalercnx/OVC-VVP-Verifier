# VVP Verifier Change Log

## Phase 2: VVP-Identity Header Parser

**Date:** 2026-01-23
**Commit:** `70fd80f`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `app/vvp/exceptions.py` | Created | Typed exceptions with error codes |
| `app/vvp/header.py` | Created | VVP-Identity header parser per §4.1A/B |
| `tests/test_header.py` | Created | 38 unit tests for header parsing |

### Summary

- Created `VVPIdentityError` exception class with factory methods for `VVP_IDENTITY_MISSING` and `VVP_IDENTITY_INVALID`
- Created `VVPIdentity` frozen dataclass with fields: `ppt`, `kid`, `evd`, `iat`, `exp`
- Implemented `parse_vvp_identity()` function:
  - Base64url decoding with padding fix
  - JSON parsing with UTF-8 validation
  - Required field validation: `ppt`, `kid`, `evd`, `iat`
  - Type validation: strings must be non-empty, integers must be actual integers (not booleans)
  - Clock skew validation for `iat` (±300s configurable)
  - Optional `exp` handling (defaults to `iat + MAX_TOKEN_AGE_SECONDS`)
- Treats `kid`/`evd` as opaque OOBI references (no URL validation)
- Does NOT validate `ppt` value (deferred to Phase 3/5 per §5.2)
- Distinguishes `VVP_IDENTITY_MISSING` (absent header) from `VVP_IDENTITY_INVALID` (parse/validation errors)

### Spec Sections Implemented

- §4.1A VVP-Identity Header (Decoded)
- §4.1B OOBI Semantics for kid/evd
- §4.2A Error Codes: VVP_IDENTITY_MISSING, VVP_IDENTITY_INVALID

### Checklist Tasks Completed

- [x] 2.1 - Create `app/vvp/header.py` module
- [x] 2.2 - Implement base64url decoding of VVP-Identity header
- [x] 2.3 - Parse JSON with fields: `ppt`, `kid`, `evd`, `iat`, `exp`
- [x] 2.4 - Validate `ppt` field exists (value validation deferred to Phase 3)
- [x] 2.5 - Validate `kid` and `evd` are present as opaque strings
- [x] 2.6 - Implement clock skew validation (±300s) on `iat`
- [x] 2.7 - Handle optional `exp`; if absent, use `iat` + 300s max age
- [x] 2.8 - Reject future `iat` beyond clock skew
- [x] 2.9 - Return structured errors: `VVP_IDENTITY_MISSING` vs `VVP_IDENTITY_INVALID`
- [x] 2.10 - Unit tests for header parsing

### Test Results

```
71 passed in 0.26s (38 new + 33 from Phase 1)
```

---

## Phase 1: Core Infrastructure

**Date:** 2026-01-23
**Commit:** `9546f37`

### Files Changed

| File | Action | Description |
|------|--------|-------------|
| `.gitignore` | Created | Python/IDE/OS ignores |
| `app/core/__init__.py` | Created | Empty package init |
| `app/core/config.py` | Created | Configuration constants per §4.1A, §5.2A/B |
| `app/vvp/api_models.py` | Replaced | Models per §3.2, §4.1-4.3, §4.2A |
| `app/vvp/verify.py` | Updated | Use new models (placeholder returns INDETERMINATE) |
| `tests/__init__.py` | Created | Test package init |
| `tests/test_models.py` | Created | 33 unit tests for Phase 1 models |
| `CLAUDE.md` | Created | Project instructions for Claude Code |
| `CHANGES.md` | Created | This change log |

### Summary

- Defined `ClaimStatus` enum (VALID, INVALID, INDETERMINATE) per §3.2
- Defined `ClaimNode` with `{required, node}` children structure per §4.3B
- Defined `ChildLink` model for explicit required/optional child relationships
- Defined `CallContext` model per §4.1
- Defined `VerifyRequest` model with required `passport_jwt` and `context` per §4.1
- Defined `VerifyResponse` model with `overall_status`, `claims`, `errors` per §4.2/§4.3
- Defined `ErrorDetail` model per §4.2
- Created 18 error codes per §4.2A with `ERROR_RECOVERABILITY` mapping
- Implemented `derive_overall_status()` function per §4.3A precedence rules
- Created configuration constants: clock skew (±300s), max token age (300s), max iat drift (5s), allowed algorithms (EdDSA)
- Updated `verify.py` to use new models (placeholder implementation)
- Created 33 unit tests covering all Phase 1 models

### Spec Sections Implemented

- §3.2 Claim Status
- §4.1 Request Models
- §4.2 Error Envelope
- §4.2A Error Code Registry
- §4.3 Response Models
- §4.3A overall_status Derivation
- §4.3B Claim Node Schema
- §4.1A, §5.2A/B Configuration Constants

### Checklist Tasks Completed

- [x] 1.1 - Create `app/core/config.py`
- [x] 1.2 - Define `ClaimStatus` enum
- [x] 1.3 - Define `ClaimNode` model
- [x] 1.4 - Define `VerifyRequest` model
- [x] 1.5 - Define `VerifyResponse` model
- [x] 1.6 - Define `ErrorDetail` model
- [x] 1.7 - Create error code constants
- [x] 1.8 - Implement `overall_status` derivation

### Test Results

```
33 passed in 0.14s
```
