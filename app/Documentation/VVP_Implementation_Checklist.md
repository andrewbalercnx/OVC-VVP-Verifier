# VVP Verifier Implementation Checklist

**Document Version:** 2.0
**Specification Version:** v1.4 FINAL
**Created:** 2026-01-23
**Last Updated:** 2026-01-23
**Status:** In Progress

---

## How to Use This Document

- Mark items complete by changing `[ ]` to `[x]`
- Add the commit SHA in the **Commit** column when completed
- Add notes in the **Comments** column as needed
- Update **Status** to reflect current phase

---

## Phase 1: Core Infrastructure

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 1.1 | Create `app/core/config.py` with configuration constants | [ ] | | Clock skew (±300s), max token age (300s), timeouts, algorithm policy |
| 1.2 | Define `ClaimStatus` enum (VALID, INVALID, INDETERMINATE) | [ ] | | Per §3.2 |
| 1.3 | Define `ClaimNode` Pydantic model with `{required, node}` children | [ ] | | Per §4.3B |
| 1.4 | Define `VerifyRequest` model (passport_jwt, context) | [ ] | | Per §4.1 |
| 1.5 | Define `VerifyResponse` model (request_id, overall_status, claims, errors) | [ ] | | Per §4.2, §4.3 |
| 1.6 | Define `ErrorDetail` model (code, message, recoverable) | [ ] | | Per §4.2 |
| 1.7 | Create error code constants per §4.2A registry (18 codes) | [ ] | | See Error Code Registry below |
| 1.8 | Implement `overall_status` derivation logic per §4.3A | [ ] | | Precedence rules |

---

## Phase 2: VVP-Identity Header Parser

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 2.1 | Create `app/vvp/header.py` module | [ ] | | |
| 2.2 | Implement base64url decoding of VVP-Identity header | [ ] | | Error: VVP_IDENTITY_INVALID on decode failure |
| 2.3 | Parse JSON with fields: `ppt`, `kid`, `evd`, `iat`, `exp` | [ ] | | |
| 2.4 | Validate `ppt` field exists | [ ] | | Value not constrained; "shaken" is valid per §4.1A |
| 2.5 | Validate `kid` and `evd` are present and are OOBI references | [ ] | | Per §4.1B OOBI semantics |
| 2.6 | Implement clock skew validation (±300s) on `iat` | [ ] | | Per §4.1A |
| 2.7 | Handle optional `exp`; if absent, use `iat` + 300s max age | [ ] | | Per §4.1A; configurable |
| 2.8 | Reject future `iat` beyond clock skew | [ ] | | Per §4.1A |
| 2.9 | Return structured errors for all failure modes | [ ] | | |
| 2.10 | Unit tests for header parsing | [ ] | | Happy path + edge cases |

---

## Phase 3: PASSporT JWT Verification

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 3.1 | Create `app/vvp/passport.py` module | [ ] | | |
| 3.2 | Parse JWT structure (header.payload.signature) | [ ] | | Error: PASSPORT_PARSE_FAILED |
| 3.3 | Reject `alg=none` | [ ] | | Per §5.1 |
| 3.4 | Reject ES256, HMAC, RSA algorithms | [ ] | | Per §5.0/§5.1 - explicitly forbidden for VVP |
| 3.5 | Accept only EdDSA (Ed25519) | [ ] | | Per §5.1 - baseline for VVP PASSporT |
| 3.6 | Return PASSPORT_FORBIDDEN_ALG for algorithm violations | [ ] | | Per §4.2A |
| 3.7 | Extract header claims: `alg`, `typ`, `ppt`, `kid` | [ ] | | |
| 3.8 | Extract VVP payload claims: `iss`, `iat`, `orig`, `dest`, `evd` (required) | [ ] | | Per VVP draft §4 |
| 3.9 | Extract optional VVP claims: `card`, `goal`, `call-reason`, `origid`, `exp` | [ ] | | VVP extensions |
| 3.10 | Validate `ppt` matches between PASSporT and VVP-Identity | [ ] | | Per §5.2 header binding |
| 3.11 | Validate `kid` binding between PASSporT and VVP-Identity | [ ] | | Per §5.2 |
| 3.12 | Defer signature verification (requires KERI key state at T) | [ ] | | Placeholder for Phase 4 |
| 3.13 | Unit tests for PASSporT parsing | [ ] | | |

---

## Phase 4: KERI Integration

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 4.1 | Add `keri>=2.0.0` to requirements.txt | [ ] | | Plus pysodium, blake3, lmdb |
| 4.2 | Create `app/vvp/keri/resolver.py` module | [ ] | | |
| 4.3 | Initialize KERI database (Habery context) | [ ] | | Using keri.app.habbing |
| 4.4 | Implement `KeriResolver.resolve(identifier: str, at_time: int)` | [ ] | | Returns KeyState at reference time T |
| 4.5 | Implement OOBI dereferencing for `kid` field | [ ] | | Must support `application/json+cesr` per §4.1B |
| 4.6 | Validate OOBI content-type is `application/json+cesr` | [ ] | | Error: VVP_OOBI_CONTENT_INVALID if wrong |
| 4.7 | Handle OOBI fetch failures | [ ] | | Error: VVP_OOBI_FETCH_FAILED (recoverable) |
| 4.8 | Implement KEL parsing via `keri.core.parsing.Parser` | [ ] | | |
| 4.9 | Implement KERI/CESR version handling per §7.1 | [ ] | | Support v1/v2, reject mismatched versions |
| 4.10 | Implement historical key state lookup at reference time T | [ ] | | Per §5.3; T = iat from VVP-Identity |
| 4.11 | Validate witness receipts at reference time T | [ ] | | Per §5.3 |
| 4.12 | Check for key rotation/revocation prior to T | [ ] | | Per §5.3; INVALID if revoked before T |
| 4.13 | Implement Ed25519 signature verification via `Verfer.verify()` | [ ] | | Using key state at T |
| 4.14 | Handle transient failures → INDETERMINATE | [ ] | | Error: KERI_RESOLUTION_FAILED |
| 4.15 | Handle cryptographically invalid state → INVALID | [ ] | | Error: KERI_STATE_INVALID |
| 4.16 | Integration tests with mock KERI infrastructure | [ ] | | |

---

## Phase 5: Dossier Fetching and Validation

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 5.1 | Create `app/vvp/dossier/fetch.py` module | [ ] | | |
| 5.2 | Create `app/vvp/dossier/model.py` module | [ ] | | |
| 5.3 | Define `ACDCNode` dataclass | [ ] | | said, issuer, schema, attributes, edges, proofs per §6.1A |
| 5.4 | Define `DossierGraph` dataclass | [ ] | | root, nodes dict per §6.1 |
| 5.5 | Implement OOBI dereference for `evd` field | [ ] | | Per §4.1B/§6.1B |
| 5.6 | Validate response content-type is `application/json+cesr` | [ ] | | Per §6.1B |
| 5.7 | Enforce timeout (configurable, e.g. 5 seconds) | [ ] | | Per §6.1B |
| 5.8 | Enforce redirect limits | [ ] | | Per §6.1B |
| 5.9 | Enforce size limit (configurable, e.g. 1MB) | [ ] | | Per §6.1B |
| 5.10 | Parse dossier using KERI/CESR parser (not generic JSON) | [ ] | | Per §4.1B/§6.1B |
| 5.11 | Handle ACDC variants: compact, partial, aggregate | [ ] | | Per §1.4/§6.1B - MUST support |
| 5.12 | Implement DAG cycle detection | [ ] | | Error: DOSSIER_GRAPH_INVALID |
| 5.13 | Validate explicit root node exists | [ ] | | Error: DOSSIER_GRAPH_INVALID |
| 5.14 | Implement "most compact form" SAID computation per ACDC spec | [ ] | | Depth-first, compute leaf SAIDs first |
| 5.15 | Verify each ACDC SAID matches recomputed value | [ ] | | Blake3-256, Error: ACDC_SAID_MISMATCH |
| 5.16 | Verify ACDC issuer signatures via KERI historical key state | [ ] | | Key state at ACDC issuance time |
| 5.17 | Verify ACDC proofs present where required | [ ] | | Error: ACDC_PROOF_MISSING |
| 5.18 | Enforce freshness/expiry policy on credentials | [ ] | | Per §7.3 - don't default to "never" |
| 5.19 | Handle fetch failures → INDETERMINATE | [ ] | | Error: DOSSIER_FETCH_FAILED |
| 5.20 | Unit tests for dossier validation | [ ] | | Including ACDC variant tests |

---

## Phase 6: Claim Derivation Engine

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 6.1 | Create `app/vvp/verify/engine.py` module | [ ] | | |
| 6.2 | Create `app/vvp/verify/claimtree.py` module | [ ] | | |
| 6.3 | Implement claim tree construction from dossier | [ ] | | |
| 6.4 | Validate all children have explicit required/optional flag | [ ] | | Per §3.3 - omission is ERROR |
| 6.5 | Implement REQUIRED child propagation: INVALID → parent INVALID | [ ] | | Per §3.3A |
| 6.6 | Implement REQUIRED child propagation: INDETERMINATE → parent INDETERMINATE | [ ] | | Per §3.3A |
| 6.7 | Implement OPTIONAL child handling (never invalidates parent) | [ ] | | Per §3.3A |
| 6.8 | Implement `overall_status` derivation from root claims | [ ] | | Per §4.3A |
| 6.9 | Support partial trees for recoverable failures | [ ] | | Per §9 |
| 6.10 | Implement short-circuit on fatal PASSporT failures | [ ] | | Per §9 |
| 6.11 | Handle DI2I delegation edges (or mark INDETERMINATE if unsupported) | [ ] | | Per §7.2 |
| 6.12 | Log all claim decisions with request_id | [ ] | | JSON format per §11 |
| 6.13 | Unit tests for claim propagation | [ ] | | All status combinations |

---

## Phase 7: API Routes

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 7.1 | Create/update `app/api/routes.py` | [ ] | | |
| 7.2 | Implement `POST /verify` endpoint | [ ] | | |
| 7.3 | Extract VVP-Identity header | [ ] | | Error: VVP_IDENTITY_MISSING if absent |
| 7.4 | Parse request body (passport_jwt, context) | [ ] | | Error: PASSPORT_MISSING if absent |
| 7.5 | Generate request_id (UUID) | [ ] | | |
| 7.6 | Wire up verification engine per §9 pseudocode | [ ] | | |
| 7.7 | Return structured response (claims or errors) | [ ] | | Per §4.2, §4.3 |
| 7.8 | Implement `GET /version` endpoint | [ ] | | Return GIT_SHA |
| 7.9 | Implement `GET /healthz` endpoint | [ ] | | Health check |
| 7.10 | Add request correlation logging middleware | [ ] | | |
| 7.11 | Integration tests for API routes | [ ] | | |

---

## Phase 8: Test Vectors

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 8.1 | Create test vector directory structure | [ ] | | tests/vectors/ |
| 8.2 | Valid VVP-Identity + valid EdDSA PASSporT + valid dossier → VALID | [ ] | | Per §10.2 |
| 8.3 | PASSporT uses forbidden algorithm (ES256) → INVALID | [ ] | | Per §10.2 |
| 8.4 | PASSporT signature invalid at reference time T → INVALID | [ ] | | Per §10.2 |
| 8.5 | Key rotated/revoked before T (historical) → INVALID | [ ] | | Per §10.2 |
| 8.6 | OOBI/KERI resolution timeout → INDETERMINATE | [ ] | | Per §10.2 |
| 8.7 | Dossier unreachable → INDETERMINATE | [ ] | | Per §10.2 |
| 8.8 | SAID mismatch under most-compact-form rule → INVALID | [ ] | | Per §10.2 |
| 8.9 | Valid compact/partial/aggregate dossier variant → VALID | [ ] | | Per §10.2 |
| 8.10 | Each vector includes: input, artefacts, T, expected tree, errors | [ ] | | Per §10.3 |
| 8.11 | Implement test vector runner | [ ] | | |
| 8.12 | CI integration for test vectors | [ ] | | GitHub Actions |

---

## Phase 9: Deployment and Verification

| # | Task | Status | Commit | Comments |
|---|------|--------|--------|----------|
| 9.1 | Update Dockerfile for new dependencies | [ ] | | libsodium, lmdb |
| 9.2 | Update requirements.txt | [ ] | | All keripy dependencies |
| 9.3 | Verify local Docker build | [ ] | | |
| 9.4 | Push to main branch | [ ] | | Triggers CI/CD |
| 9.5 | Verify GitHub Actions workflow succeeds | [ ] | | |
| 9.6 | Verify new ACA revision created | [ ] | | az containerapp revision list |
| 9.7 | Verify /healthz endpoint responds | [ ] | | curl command |
| 9.8 | Verify /version returns correct SHA | [ ] | | |
| 9.9 | End-to-end test with real request | [ ] | | |

---

## Error Code Registry (v1.4 §4.2A)

These are the **18 error codes** defined in the v1.4 FINAL specification:

| Code | Layer | Recoverable | Usage |
|------|-------|-------------|-------|
| VVP_IDENTITY_MISSING | Protocol | N | Missing VVP-Identity header |
| VVP_IDENTITY_INVALID | Protocol | N | Header decode/parse failure |
| VVP_OOBI_FETCH_FAILED | Protocol | Y | OOBI dereference failed |
| VVP_OOBI_CONTENT_INVALID | Protocol | N | OOBI content-type/format invalid |
| PASSPORT_MISSING | Protocol | N | Missing passport_jwt in request body |
| PASSPORT_PARSE_FAILED | Protocol | N | PASSporT JWT cannot be decoded |
| PASSPORT_SIG_INVALID | Crypto | N | PASSporT signature invalid |
| PASSPORT_FORBIDDEN_ALG | Crypto | N | PASSporT uses forbidden algorithm |
| PASSPORT_EXPIRED | Protocol | N | PASSporT expired per iat/exp policy |
| DOSSIER_URL_MISSING | Evidence | N | No evd OOBI present in VVP-Identity |
| DOSSIER_FETCH_FAILED | Evidence | Y | Unable to retrieve dossier from evd |
| DOSSIER_PARSE_FAILED | Evidence | N | Dossier content cannot be parsed |
| DOSSIER_GRAPH_INVALID | Evidence | N | Dossier invalid (cycle, missing root, etc.) |
| ACDC_SAID_MISMATCH | Crypto | N | ACDC SAID does not match most-compact-form |
| ACDC_PROOF_MISSING | Crypto | N | Required proof/signature missing |
| KERI_RESOLUTION_FAILED | KERI | Y | Unable to resolve issuer key state |
| KERI_STATE_INVALID | KERI | N | Resolved key state fails constraints |
| INTERNAL_ERROR | Verifier | Y | Unexpected verifier failure |

---

## Summary

| Phase | Total Tasks | Completed | Percentage |
|-------|-------------|-----------|------------|
| 1. Core Infrastructure | 8 | 0 | 0% |
| 2. VVP-Identity Header | 10 | 0 | 0% |
| 3. PASSporT JWT | 13 | 0 | 0% |
| 4. KERI Integration | 16 | 0 | 0% |
| 5. Dossier Validation | 20 | 0 | 0% |
| 6. Claim Engine | 13 | 0 | 0% |
| 7. API Routes | 11 | 0 | 0% |
| 8. Test Vectors | 12 | 0 | 0% |
| 9. Deployment | 9 | 0 | 0% |
| **TOTAL** | **112** | **0** | **0%** |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-23 | Initial checklist |
| 1.1 | 2026-01-23 | Fixed: ppt validation, error codes (9), 60s expiration layer, historical key state, most-compact-form SAID |
| 2.0 | 2026-01-23 | Updated for v1.4 FINAL: 18 error codes, OOBI semantics (§4.1B), EdDSA mandatory/ES256 forbidden (§5.0-5.1), 300s default max age, header binding (§5.2), ACDC variants support, KERI versioning (§7.1), DI2I delegation (§7.2), freshness policy (§7.3), expanded test vectors |

---

**Last Updated:** 2026-01-23
**Next Review:** After Phase 1 completion
