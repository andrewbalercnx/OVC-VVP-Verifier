# Sprint 54: Open-Source Standalone VVP Verifier

## Problem Statement

The VVP Verifier has grown across 25+ sprints into a comprehensive but complex implementation with deep ties to the monorepo's `common/` package, extensive UI templates, caching systems, background workers, and internal project tooling. External developers cannot easily adopt it. This sprint extracts the essential verification logic into a clean, standalone repository suitable for open-source release.

## Spec References

- §5.0, §5.1: EdDSA (Ed25519) mandatory signature algorithm
- §5.2A: iat drift ≤ 5 seconds
- §5.2B: Max PASSporT validity and clock skew defaults
- §9: Verification pipeline phases
- §3.3A: Status propagation precedence rules
- §5.1.1-2.9: Revocation checking
- §5A Steps 10-11: Authorization (TN rights) validation
- §6.1: Dossier DAG validation (cycle detection, single root)

## Current State

The monorepo verifier spans ~27,000 lines across 65+ files with 18 KERI modules (including Tier 2 KEL resolution, OOBI, witness pool), 13 ACDC files, 7 dossier files, vetter/brand/goal modules, and extensive UI templates. It depends on `common/vvp` (~2,400 lines) for SIP, canonical serialization, schemas, models, and TEL client.

## Proposed Solution

### Approach

Create a new orphan branch `vvp-verifier` containing a self-contained FastAPI + SIP UDP verifier. All `common/` dependencies are inlined. Complex features (Tier 2 KEL, vetter constraints, brand/goal verification, callee verification, HTMX UI) are excluded. The result is a ~5,000-6,000 line codebase with 9-phase verification, two-tier caching, background revocation checking, and minimal documentation.

**This is a subset implementation** — it implements the core VVP verification pipeline but intentionally excludes advanced governance features. See "Spec Compliance Matrix" below for the full scope declaration.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Git subtree split | Preserves history | Carries monorepo pollution, complex imports | Sprint spec requires orphan branch |
| Keep common/ as submodule | Reuses shared code | Defeats standalone goal | External dependency |
| Copy full verifier verbatim | Less work | 27K lines, 65 files, broken imports | Too complex for open-source |

### Spec Compliance Matrix

The standalone verifier is a **subset implementation** of the VVP specification. This matrix declares scope:

| Spec Section | Feature | Status | Notes |
|-------------|---------|--------|-------|
| §5.0, §5.1 | EdDSA (Ed25519) signature verification | **Implemented** | Tier 1 (direct AID key) only |
| §5.2A | iat drift ≤ 5 seconds | **Implemented** | Normative constant |
| §5.2B | Max PASSporT validity, clock skew | **Implemented** | Configurable defaults |
| §9 Phases 2-3 | VVP-Identity + PASSporT parse | **Implemented** | Full compliance |
| §9 Phase 4 | KERI signature verification (Tier 1) | **Implemented** | Non-transferable Ed25519 AIDs only (`B` prefix). Transferable AIDs (`D` prefix) rejected with INDETERMINATE |
| §9 Phase 4 | KERI signature verification (Tier 2) | **Excluded** | Requires KEL infrastructure; transferable AIDs fail-closed with `KERI_RESOLUTION_FAILED` |
| §6.1 | Dossier fetch, parse, DAG validation | **Implemented** | Cycle detection, single root, CESR + JSON formats |
| §9 Phase 5.5 | ACDC chain validation (SAID + signature) | **Implemented** | Inline verification, no external schema resolution |
| §5.1.1-2.9 | Revocation checking (TEL) | **Implemented** | Inline TEL parsing + witness queries + dossier TEL fallback |
| §6.1B | Dossier fetch constraints | **Implemented** | Timeout 5s, size 1MB |
| §5A Step 10 | Party authorization (Case A + B) | **Implemented** | APE lookup, delegation chain walk (max depth 10) |
| §5A Step 11 | TN rights validation | **Implemented** | TNAlloc credential check, E.164 range matching |
| §3.3A | Status propagation precedence | **Implemented** | INVALID > INDETERMINATE > VALID |
| §4.2A | Error code completeness | **Partial** | 20 codes covering all implemented features; excluded features return no error (not evaluated). **Reconciliation:** Every `VerifyResponse` includes a mandatory `capabilities` dict (Step 11) that explicitly declares which phases were evaluated and which were not. Consumers inspect `capabilities` to distinguish "checked and passed" from "not checked." This avoids silent pass-by-omission without requiring spurious INDETERMINATE for features that never ran. See Step 11 "Capability signaling" and "Subset VALID semantics" for the full contract. |
| §5B | Callee verification | **Excluded** | Separate use case; not needed for basic verifier |
| §5.1.1-2.13 | Goal/business logic | **Excluded** | Advanced governance feature |
| §5.1.1-2.12 | Brand credential verification | **Excluded** | Advanced feature; brand_name extracted from dossier if present but not validated |
| Sprint 40 | Vetter certification constraints | **Excluded** | Advanced governance (geographic/jurisdictional) |
| §9 Phase 13 | SIP context alignment | **Excluded** | Requires SIP-layer integration beyond redirect server scope |

**Excluded features** are documented in ARCHITECTURE.md with rationale. The verifier returns results only for implemented phases — excluded phases are not evaluated (no false INDETERMINATE from missing features). **Every `VerifyResponse` includes a mandatory `capabilities` dict** (see Step 11, "Capability signaling") that declares each feature as `"implemented"`, `"rejected"`, or `"not_implemented"`, giving consumers machine-readable evidence of which phases ran and which did not.

### Detailed Design

#### Repository Structure

```
vvp-verifier/                           # On orphan branch 'vvp-verifier'
├── app/
│   ├── __init__.py
│   ├── main.py                         # FastAPI app + SIP server startup (lifespan)
│   ├── config.py                       # Configuration (env vars, spec constants, cache settings)
│   ├── sip/
│   │   ├── __init__.py
│   │   ├── models.py                   # SIPRequest, SIPResponse dataclasses
│   │   ├── parser.py                   # RFC 3261 SIP message parser
│   │   ├── builder.py                  # SIP 302/4xx response builder
│   │   ├── transport.py                # AsyncIO UDP server
│   │   └── handler.py                  # INVITE handler → verify → 302 redirect
│   ├── vvp/
│   │   ├── __init__.py
│   │   ├── verify.py                   # 9-phase verification pipeline orchestrator
│   │   ├── header.py                   # VVP-Identity header parser (base64url JSON)
│   │   ├── passport.py                 # PASSporT JWT parser & validator
│   │   ├── signature.py                # Ed25519 signature verification (Tier 1 only)
│   │   ├── dossier.py                  # Fetch, parse, DAG build/validate, LRU+TTL cache
│   │   ├── acdc.py                     # ACDC model, SAID computation, chain validation
│   │   ├── cesr.py                     # CESR decoding (PSS signatures, count codes)
│   │   ├── canonical.py                # KERI canonical JSON serialization
│   │   ├── schema.py                   # Schema SAID registry (vLEI schemas)
│   │   ├── models.py                   # ClaimNode, VerifyResponse, ErrorCode
│   │   ├── exceptions.py               # VVPIdentityError, PassportError, etc.
│   │   ├── authorization.py             # §5A Steps 10-11: party auth + TN rights
│   │   ├── tel.py                      # TEL client: inline TEL parsing + witness queries
│   │   ├── cache.py                    # Verification result cache (LRU+TTL, config-fingerprinted)
│   │   └── revocation.py               # Background revocation checker (async worker)
│   └── templates/
│       └── index.html                  # Single-page verification UI (vanilla JS)
├── tests/
│   ├── __init__.py
│   ├── conftest.py                     # Shared fixtures (test keys, JWTs, mock dossiers)
│   ├── test_header.py                  # VVP-Identity parser tests
│   ├── test_passport.py                # PASSporT parser tests
│   ├── test_sip.py                     # SIP parser/builder tests
│   ├── test_cache.py                   # Cache and revocation checker tests
│   └── test_verify.py                  # Integration verification tests
├── pyproject.toml                      # Dependencies and project metadata
├── Dockerfile
├── .dockerignore
├── .gitignore
├── LICENSE                             # MIT License (Rich Connexions Ltd)
├── README.md                           # Quick start, usage, configuration
├── ARCHITECTURE.md                     # System design and data flow
├── ALGORITHMS.md                       # Cryptographic algorithms and spec refs
└── SUPPORT.md                          # Getting help, contributing
```

#### Implementation Steps

##### Step 1: Repository Setup (orphan branch + scaffolding)

Create orphan branch `vvp-verifier` with no monorepo history:
```bash
git checkout --orphan vvp-verifier
git rm -rf .
```

Set up project scaffolding:
- `pyproject.toml` — minimal dependencies (fastapi, uvicorn, pydantic, pysodium, httpx, blake3, jinja2)
- `.gitignore` (Python standard: __pycache__, .venv, *.pyc, .pytest_cache)
- `.dockerignore` (.git, __pycache__, .venv, tests)
- `LICENSE` — MIT, copyright Rich Connexions Ltd
- Empty `app/` and `tests/` packages with `__init__.py`

All `.py` files get copyright header:
```python
# Copyright (c) Rich Connexions Ltd. All rights reserved.
# Licensed under the MIT License. See LICENSE for details.
```

##### Step 2: Configuration (`app/config.py`)

**Source:** `services/verifier/app/core/config.py` (575 lines → ~120 lines)

Extract and simplify:
- Normative constants: `MAX_IAT_DRIFT_SECONDS = 5`, `ALGORITHM = "EdDSA"`, `PPT = "vvp"`
- Configurable defaults: `CLOCK_SKEW_SECONDS = 300`, `MAX_TOKEN_AGE_SECONDS = 300`
- All env vars from Sprint 54 spec table (Network, Verification, Caching, Logging)
- Config fingerprint function for cache invalidation

**Remove:** vetter config, brand config, goal config, Tier 2 config, callee config, UI config, witness pool/GLEIF discovery config

##### Step 3: SIP Modules (`app/sip/`)

**Source:** `common/vvp/sip/` (4 files, ~900 lines → ~900 lines)

Direct extraction with minimal changes:
- `models.py` — SIPRequest, SIPResponse dataclasses (from `common/vvp/sip/models.py`, 168 lines)
- `parser.py` — RFC 3261 parser (from `common/vvp/sip/parser.py`, 176 lines)
- `builder.py` — 302/4xx response builder (from `common/vvp/sip/builder.py`, 238 lines)
- `transport.py` — AsyncIO UDP server (from `common/vvp/sip/transport.py`, 315 lines)

**Changes:** Update imports from `common.vvp.sip` → relative `from . import` or `from app.sip`. Remove any references to monitor integration.

##### Step 4: SIP Handler (`app/sip/handler.py`)

**Source:** `services/sip-verify/app/verify/handler.py` pattern (299 lines → ~150 lines)

New file implementing:
- Parse incoming SIP INVITE
- Extract Identity header (PASSporT JWT)
- Extract P-VVP-Identity header (base64url JSON with kid, evd, iat, exp)
- Call `verify()` pipeline from `app.vvp.verify`
- Build SIP 302 redirect with X-VVP-Status, X-VVP-Brand-Name, X-VVP-Caller-ID, X-VVP-Error headers
- Return 4xx for missing/invalid headers

**Remove:** monitor integration, verify-callee delegation, external verifier API calls, audit logging

##### Step 5: VVP-Identity Header Parser (`app/vvp/header.py`)

**Source:** `services/verifier/app/vvp/header.py` (159 lines → ~120 lines)

Direct extraction:
- Parse base64url-encoded JSON header
- Validate required fields: ppt, kid, evd, iat
- Validate optional fields: exp
- Return VVPIdentity dataclass

**Changes:** Remove monorepo-specific imports. Self-contained.

##### Step 6: PASSporT Parser (`app/vvp/passport.py`)

**Source:** `services/verifier/app/vvp/passport.py` (583 lines → ~250 lines)

Simplify:
- JWT parsing: split on `.`, base64url decode header/payload/signature
- Validate: alg=EdDSA, ppt=vvp
- Extract: orig, dest, evd claims
- Binding validation: iat drift ≤5s (§5.2A), kid match, exp consistency
- **§5.2B enforcement:**
  - **Max token age:** If `exp` absent, enforce `iat + VVP_MAX_TOKEN_AGE_SECONDS` (default 300s). Reject with `PASSPORT_EXPIRED` if token is older than max age.
  - **Clock skew tolerance:** When validating `iat` and `exp`, allow `±VVP_CLOCK_SKEW_SECONDS` (default 300s) to accommodate clock differences between issuer and verifier. Reject with `PASSPORT_EXPIRED` if outside bounds.
- Return Passport dataclass

**Tests:** Include test for max_token_age enforcement (token older than 300s without exp → PASSPORT_EXPIRED), clock skew within bounds (accepted), clock skew exceeded (rejected).

**Remove:** Tier 2 key state binding, extended claim extraction for vetter/brand/goal, callee-specific validation

##### Step 7: Ed25519 Signature (`app/vvp/signature.py`)

**Source:** `services/verifier/app/vvp/keri/signature.py` (347 lines → ~100 lines)

Tier 1 only with **fail-closed transferable AID handling**:
- Parse the AID prefix derivation code to determine identifier type
- **Non-transferable AIDs (`B` prefix, 44 chars):** CESR-decode to extract raw 32-byte Ed25519 public key. Verify signature over `{header}.{payload}` bytes using `pysodium.crypto_sign_verify_detached()`.
- **Transferable AIDs (`D` prefix, 44 chars):** **Reject with INDETERMINATE** and `KERI_RESOLUTION_FAILED` error. Transferable AIDs require KEL resolution to determine current key state (the AID prefix key may have been rotated). Without Tier 2 infrastructure, we cannot safely verify these signatures. The error message explains: "Transferable AID requires KEL resolution (Tier 2) which is not supported by this verifier."
- **Unknown prefix codes:** Reject with INDETERMINATE and `PASSPORT_SIG_INVALID`.
- Raise SignatureInvalidError on verification failure.

**Supported Identifier Types:** Only non-transferable Ed25519 AIDs (`B` prefix) are supported. This is documented in ARCHITECTURE.md under "Supported Identifier Types" and in the capabilities block.

**Tests:** Include test for non-transferable AID (valid), transferable AID (rejected with KERI_RESOLUTION_FAILED), and unknown prefix (rejected).

**Remove:** Tier 2 KEL resolution, witness queries, key rotation handling, key state validation

##### Step 8: CESR Module (`app/vvp/cesr.py`)

**Source:** `services/verifier/app/vvp/keri/cesr.py` (914 lines → ~200 lines)

Keep:
- Derivation code table for Ed25519 AID prefix decoding
- PSS (pre-signed signature) decoding from CESR-encoded attachments
- Basic count code parsing for dossier CESR streams (needed for dossier.py)
- Base64url ↔ raw bytes conversion

**Remove:** Full CESR stream parsing for KEL events, forward-compat unknown codes, indexed signature groups, receipt parsing

##### Step 9: Canonical Serialization (`app/vvp/canonical.py`)

**Source:** `common/vvp/canonical/keri_canonical.py` (191 lines → ~150 lines)

Direct extraction:
- KERI-compliant field ordering for deterministic JSON serialization
- Blake3-256 SAID computation
- Compact form detection and SAID placeholder handling

**Changes:** Remove `common.vvp` import paths. Inline any needed utilities.

##### Step 10: Schema Registry (`app/vvp/schema.py`)

**Source:** `common/vvp/schema/registry.py` (152 lines → ~80 lines)

Simplify to static mapping:
- Known vLEI schema SAIDs → credential type name
- Includes: Legal Entity, QVI, OOR, ECR, TN Allocation, Engagement Context Role
- `get_credential_type(schema_said) → Optional[str]`

**Unknown schema SAID behavior:** When `get_credential_type()` returns `None` (unknown SAID), the credential is treated as type `"unknown"`. This has specific impacts:
- **Chain validation:** Unknown-typed credentials are still validated for SAID integrity and signature. Chain walk continues through them.
- **Authorization (Phase 9):** `_find_credentials_by_type()` will not match unknown credentials when looking for APE, DE, or TNAlloc types. If the authorization phase cannot find the required credential types, it fails with `AUTHORIZATION_FAILED` or `TN_RIGHTS_INVALID`. This is **fail-closed** behavior — unknown schemas cannot grant authorization.
- **Tests:** Include a test case with an unknown schema SAID to verify fail-closed authorization behavior.

**Remove:** dynamic schema resolution, OOBI fetching, schema store, schema validation, schema cache

##### Step 11: Models (`app/vvp/models.py`)

**Source:** `services/verifier/app/vvp/api_models.py` (403 lines → ~250 lines)

Keep:
- `ClaimNode`, `ClaimStatus`, `ChildLink` — claim tree structure
- `ErrorDetail`, `ErrorCode` enum (20 codes covering all implemented features)
- `VerifyRequest`, `VerifyResponse` — API models
- `derive_overall_status()` — §3.3A precedence (INVALID > INDETERMINATE > VALID)
- `ERROR_RECOVERABILITY` mapping
- `DelegationChainResponse`, `DelegationNodeResponse` — for chain display
- `capabilities` field on `VerifyResponse` — lists implemented spec sections to signal subset behavior

**Capability signaling (addresses "NOT_EVALUATED" concern):**

The `VerifyResponse` includes a `capabilities` dict listing which spec phases were evaluated:
```python
capabilities: Dict[str, str] = {
    "signature_tier1_nontransferable": "implemented",
    "signature_tier1_transferable": "rejected",  # fail-closed, requires Tier 2
    "signature_tier2": "not_implemented",
    "dossier_validation": "implemented",
    "acdc_chain": "implemented",
    "revocation": "implemented",
    "authorization": "implemented",
    "brand_verification": "not_implemented",
    "goal_verification": "not_implemented",
    "vetter_constraints": "not_implemented",
    "sip_context": "not_implemented",
    "callee_verification": "not_implemented",
}
```

The `/healthz` endpoint also returns this same `capabilities` block.

**`capabilities` is mandatory** — it is always present in every `VerifyResponse` and `/healthz` response. It is NOT optional. This is the API contract that makes subset behavior unambiguous.

**"Subset VALID" semantics (documented in README + ARCHITECTURE):**
- A `VALID` result means "valid for all phases listed as `implemented` in `capabilities`"
- Consumers **MUST** inspect `capabilities` before treating `VALID` as spec-complete
- Phases listed as `not_implemented` or `rejected` were not evaluated and do not contribute to `overall_status`
- This contract is documented in README.md (API Reference section) and ARCHITECTURE.md (Spec Compliance section)

This avoids false VALID claims without introducing spurious INDETERMINATE results for features that were never intended to run.

**§4.2A Reconciliation:** The VVP spec requires error code completeness. This subset implementation satisfies that requirement for all **implemented** phases (20 ErrorCodes cover every failure mode that can occur). For **excluded** phases, the `capabilities` dict serves as the machine-readable signal: any feature marked `"not_implemented"` or `"rejected"` was not evaluated. Consumers that require full spec coverage can check `capabilities` and reject results where needed features show `"not_implemented"`. This is the same pattern used by TLS cipher suite negotiation — the server advertises what it supports, and the client decides if that meets its requirements.

ErrorCode enum (20 codes aligned to spec compliance matrix):
```python
class ErrorCode(str, Enum):
    # Protocol layer (VVP-Identity + PASSporT)
    VVP_IDENTITY_MISSING = "VVP_IDENTITY_MISSING"
    VVP_IDENTITY_INVALID = "VVP_IDENTITY_INVALID"
    VVP_OOBI_FETCH_FAILED = "VVP_OOBI_FETCH_FAILED"       # recoverable — emitted by TEL witness OOBI extraction
    PASSPORT_MISSING = "PASSPORT_MISSING"
    PASSPORT_PARSE_FAILED = "PASSPORT_PARSE_FAILED"
    PASSPORT_EXPIRED = "PASSPORT_EXPIRED"
    PASSPORT_FORBIDDEN_ALG = "PASSPORT_FORBIDDEN_ALG"
    # Crypto layer
    PASSPORT_SIG_INVALID = "PASSPORT_SIG_INVALID"
    ACDC_SAID_MISMATCH = "ACDC_SAID_MISMATCH"
    ACDC_PROOF_MISSING = "ACDC_PROOF_MISSING"
    # Evidence layer (Dossier)
    DOSSIER_URL_MISSING = "DOSSIER_URL_MISSING"
    DOSSIER_FETCH_FAILED = "DOSSIER_FETCH_FAILED"          # recoverable
    DOSSIER_PARSE_FAILED = "DOSSIER_PARSE_FAILED"
    DOSSIER_GRAPH_INVALID = "DOSSIER_GRAPH_INVALID"
    # KERI layer
    KERI_RESOLUTION_FAILED = "KERI_RESOLUTION_FAILED"      # recoverable — emitted by TEL witness OOBI resolution
    # Revocation layer
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    # Authorization layer (§5A Steps 10-11)
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    TN_RIGHTS_INVALID = "TN_RIGHTS_INVALID"
    # System
    INTERNAL_ERROR = "INTERNAL_ERROR"                       # recoverable
```

Recoverability mapping preserved from monorepo:
```python
ERROR_RECOVERABILITY = {
    "VVP_OOBI_FETCH_FAILED": True,
    "DOSSIER_FETCH_FAILED": True,
    "KERI_RESOLUTION_FAILED": True,
    "INTERNAL_ERROR": True,
    # All others: False (non-recoverable)
}
```

**Excluded codes** (features not implemented): `CONTEXT_MISMATCH`, `BRAND_CREDENTIAL_INVALID`, `GOAL_REJECTED`, `DIALOG_MISMATCH`, `ISSUER_MISMATCH`, `VETTER_ECC_UNAUTHORIZED`, `VETTER_JURISDICTION_UNAUTHORIZED`, `VETTER_CERTIFICATION_MISSING`, `VETTER_CERTIFICATION_INVALID`. These are documented in ARCHITECTURE.md as out-of-scope.

**Remove:** VetterConstraintInfo, IssuerIdentityInfo, brand/goal models, callee models, ToIPWarningDetail

##### Step 12: Exceptions (`app/vvp/exceptions.py`)

**Source:** `services/verifier/app/vvp/exceptions.py` (95 lines → ~60 lines)

Extract:
- `VVPIdentityError`, `PassportError`
- `SignatureInvalidError`
- `DossierFetchError`, `DossierParseError`, `DossierGraphError`
- Base `VVPError` class

**Remove:** vetter/brand/goal-specific exceptions, KERI resolution exceptions

##### Step 13: ACDC Module (`app/vvp/acdc.py`)

**Source:** Multiple files merged (~5,000 lines across 13 files → ~500 lines single file)

Merge from:
- `common/vvp/models/acdc.py` (222 lines) — ACDC dataclass
- `services/verifier/app/vvp/acdc/parser.py` (315 lines) — Parse ACDC from JSON
- `services/verifier/app/vvp/acdc/graph.py` (796 lines) — DAG construction, edge resolution, cycle detection
- `services/verifier/app/vvp/acdc/verifier.py` (1,017 lines) — SAID integrity, signature verify, chain walk

Keep:
- ACDC dataclass (issuer, schema, attributes, edges, signatures, raw)
- `parse_acdc(data: dict) → ACDC` — extract fields from JSON
- `build_credential_graph(acdcs: List[ACDC]) → dict` — node index + edges
- `validate_acdc_said(acdc: ACDC) → bool` — recompute SAID, compare
- `verify_acdc_signature(acdc: ACDC, ...) → bool` — Ed25519 verify issuer sig
- `verify_chain(dag, ...) → ClaimNode` — walk from root, verify each credential

**Remove:** schema resolver (OOBI-based), schema cache, schema fetcher, schema validator, vlei_chain deep resolution, external credential resolution, delegation chain multi-level validation, compact/partial variant handling beyond basic detection

##### Step 14: Dossier Module (`app/vvp/dossier.py`)

**Source:** Multiple files merged (~2,050 lines → ~400 lines single file)

Merge from:
- `common/vvp/dossier/fetch.py` (91 lines) — HTTP GET with size/timeout
- `services/verifier/app/vvp/dossier/parser.py` (301 lines) — Parse CESR or JSON → ACDCs
- `services/verifier/app/vvp/dossier/validator.py` (861 lines) — DAG construction, cycle detect, single root
- `common/vvp/dossier/cache.py` (537 lines) — LRU+TTL cache, SAID secondary index
- `common/vvp/models/dossier.py` (161 lines) — DossierDAG model

Keep:
- `DossierDAG` dataclass (nodes, edges, root)
- `fetch_dossier(url, timeout, max_size) → bytes` — async HTTP GET via httpx
- `parse_dossier(raw: bytes) → List[ACDC]` — detect format, parse CESR or JSON
- `build_dag(acdcs) → DossierDAG` — node index, edge extraction
- `validate_dag(dag) → List[ErrorDetail]` — cycle detection, root identification
- `DossierCache` class — LRU+TTL, keyed by URL, SAID secondary index for invalidation
- `CachedDossier` dataclass — parsed result with metadata

**Remove:** trust establishment tracking, complex metrics, fire-and-forget revocation tasks from cache

##### Step 15: TEL Client (`app/vvp/tel.py`)

**Source:** `common/vvp/keri/tel_client.py` (777 lines → ~350 lines)

Preserve Phase 9.4 TEL resolution fixes (inline TEL parsing + registry OOBI discovery):

**Data structures:**
- `TELEvent` dataclass (type, credential_said, registry_said, sequence, datetime, digest)
- `RevocationResult` dataclass (status, credential_said, registry_said, issuance_event, revocation_event, error, source)
- `ChainRevocationResult` dataclass (chain_status, credential_results, revoked_credentials, check_complete, errors)
- `CredentialStatus` enum: ACTIVE, REVOKED, UNKNOWN, ERROR

**Core functions (all preserved from monorepo):**
- `check_revocation(credential_said, registry_said, oobi_url) → RevocationResult`
  - Cache lookup → OOBI resolution → witness queries → UNKNOWN fallback
  - Endpoint patterns: Provenant `/query?typ=tel&vcid={said}`, standard KERI `/tels/{registry_said}`
- `_extract_tel_events(data: str) → List[TELEvent]` — **inline CESR/JSON TEL parsing** (critical Phase 9.4 fix)
  - Try JSON first, handle Provenant wrapper `{"details": "...CESR..."}`, parse raw CESR bracket counting
  - Extract event types: `iss` (issuance), `rev`/`brv` (revocation)
- `parse_dossier_tel(dossier_data, credential_said, registry_said) → RevocationResult` — parse TEL from dossier CESR stream without network
- `check_revocation_with_fallback(credential_said, registry_said, dossier_data, oobi_url) → RevocationResult`
  - Dossier TEL first (if REVOKED → return immediately, revocation is permanent)
  - Then witness query for live status (dossier may be stale)
- `check_chain_revocation(chain_info, dossier_data, oobi_url) → ChainRevocationResult`
  - Parallel check all credentials via `asyncio.gather`
  - REVOKED if ANY credential revoked; ACTIVE only if ALL active AND chain complete
- `extract_witness_base_url(oobi_url) → str` — parse OOBI URL to witness base URL

**Witness resolution:**
- Static `VVP_WITNESS_URLS` from config (replaces dynamic WitnessPool)
- `DEFAULT_WITNESSES` fallback (Provenant OVC stage witnesses)
- Extract witness from OOBI URL when available

**Remove:** WitnessPool class, GLEIF discovery, per-request witness extraction from KEL, _use_witness_pool flag

##### Step 16: Verification Result Cache (`app/vvp/cache.py`)

**Source:** `services/verifier/app/vvp/verification_cache.py` (383 lines → ~300 lines)

Near-direct extraction:
- `CachedDossierVerification` dataclass (dossier_url, passport_kid, dag, chain_claim, contained_saids, revocation_status, timestamps)
- `VerificationResultCache` with LRU+TTL using OrderedDict
- `RevocationStatus` enum (UNDEFINED/UNREVOKED/REVOKED)
- Config fingerprinting: SHA256 of validation-affecting settings → auto-invalidate on change
- Deep-copy on read for safety
- Only cache VALID chain results
- `update_revocation_all_for_url()` — atomic update across all (url, kid) variants
- `update_revocation_timestamp_all_for_url()` — timestamp update

**Changes:** Update import paths. Simplify config fingerprint to fewer config values.

##### Step 17: Background Revocation Checker (`app/vvp/revocation.py`)

**Source:** `services/verifier/app/vvp/revocation_checker.py` (201 lines → ~180 lines)

Near-direct extraction:
- `BackgroundRevocationChecker` class
- Single async worker, queue-based, dedup by dossier URL
- Configurable recheck interval (default 300s)
- `enqueue(dossier_url)` — add URL for checking
- `needs_recheck(timestamp) → bool` — check staleness
- `start()` / `stop()` — lifecycle management
- REVOKED is permanent (never downgraded)
- Preserve existing status on query errors (no false downgrades)

**Changes:** Update import paths from `app.vvp.verification_cache` → `app.vvp.cache`, `app.vvp.keri.tel_client` → `app.vvp.tel`.

##### Step 18: Verification Pipeline (`app/vvp/verify.py`)

**Source:** `services/verifier/app/vvp/verify.py` (1,911 lines → ~500 lines)

Major simplification to 9-phase pipeline:

| Phase | Description | Source Module |
|-------|-------------|---------------|
| 1 | Parse VVP-Identity | `header.py` |
| 2 | Parse PASSporT | `passport.py` |
| 3 | Bind PASSporT ↔ Identity | `passport.py` |
| 4 | Verify Signature (Ed25519 Tier 1) | `signature.py` |
| 5 | Fetch Dossier (with LRU cache) | `dossier.py` |
| 6 | Validate DAG | `dossier.py` |
| 7 | Verify ACDC Chain (with result cache) | `acdc.py`, `cache.py` |
| 8 | Check Revocation (TEL + background) | `tel.py`, `revocation.py` |
| 9 | Validate Authorization + TN Rights | `authorization.py` |

**Phase 9 — Authorization Algorithm (§5A Steps 10-11):**

The standalone verifier preserves the full authorization algorithm from `services/verifier/app/vvp/authorization.py`, extracted into `app/vvp/authorization.py` (~300 lines):

**Step 10 — Party Authorization (`verify_party_authorization`):**
- Input: `AuthorizationContext(pss_signer_aid, orig_tn, dossier_acdcs)`
- **Case A (no delegation):** Find APE credential where `issuee == pss_signer_aid`. If found → VALID, authorized_aid = issuee.
- **Case B (with delegation):** Find DE credentials where `issuee == pss_signer_aid`. Walk delegation chain via `_walk_de_chain()` (DE→DE→APE, max depth 10, cycle detection). If chain resolves to APE → VALID, authorized_aid = APE issuee.
- **Failure:** No matching APE found → INVALID with `AUTHORIZATION_FAILED`

**Step 11 — TN Rights Validation (`verify_tn_rights`):**
- Input: authorized_aid from Step 10, orig_tn from PASSporT
- Find TNAlloc credentials in dossier where `issuee == authorized_aid`
- Parse orig_tn as E.164 range
- For each bound TNAlloc: extract TN data from `attributes.tn/phone/allocation`, parse as TN allocation (ranges + lists), check `is_subset(orig_ranges, alloc_ranges)`
- If any TNAlloc covers orig_tn → VALID. If none → INVALID with `TN_RIGHTS_INVALID`

**Helper functions preserved:**
- `_walk_de_chain(de, dossier_acdcs, max_depth=10)` — delegation chain traversal
- `_find_delegation_target(de, dossier_acdcs)` — resolve DE edge targets (checks edge names: delegation, d, delegate, delegator, issuer)
- `_find_ape_referencing_de(de_said, dossier_acdcs)` — find APE referencing a terminal DE
- `_get_issuee(acdc)` — extract issuee from attributes (i, issuee, or holder field)
- `_find_credentials_by_type(dossier_acdcs, cred_type)` — filter by credential type

Cache integration:
1. Phases 1-4 always run (per-request: header, PASSporT, signature are unique)
2. Phase 5 checks dossier cache → cache hit skips HTTP fetch
3. Phases 6-7 check verification result cache → hit skips chain validation
4. Phase 8: if cached revocation is fresh → use it; if stale → return cached + enqueue background re-check; if REVOKED → INVALID immediately
5. Phase 9 always runs (per-request TN validation)

Claim tree: essential nodes preserving §3.3A structure:
```
caller_authorised
├── passport_verified (REQUIRED)
│   ├── identity_valid (REQUIRED)
│   └── signature_valid (REQUIRED)
├── dossier_verified (REQUIRED)
│   ├── chain_verified (REQUIRED)
│   └── revocation_clear (REQUIRED)
└── authorization_valid (REQUIRED)
    ├── party_authorized (REQUIRED)   — §5A Step 10
    └── tn_rights_valid (REQUIRED)    — §5A Step 11
```

**Remove from monorepo verify.py:**
- Tier 2 signature verification path (KEL resolution)
- Callee verification (§5B — separate use case)
- Vetter constraint checking (Phase 40 — advanced governance)
- Brand credential verification (advanced feature; brand_name passthrough only)
- Goal/business logic verification (advanced governance)
- SIP context alignment (Phase 13 — beyond redirect server scope)
- DID:web conversion
- Timing instrumentation (PhaseTimer)

**Preserve from monorepo verify.py:**
- Authorization phase (§5A Steps 10-11) — full algorithm in `authorization.py`
- Inline TEL parsing and dossier TEL fallback in `tel.py`
- Status propagation per §3.3A

##### Step 19: FastAPI Application (`app/main.py`)

**Source:** Patterns from `services/verifier/app/main.py` + `services/sip-verify/app/main.py` → ~300 lines

New file:
- FastAPI app with async lifespan context manager
- `GET /` — serve HTML template via Jinja2
- `POST /verify` — JSON API: accept VerifyRequest, return VerifyResponse
- `GET /healthz` — health check (returns service status, cache stats, `capabilities` block listing implemented spec sections)
- Lifespan startup: initialize SIP UDP transport, start background revocation checker
- Lifespan shutdown: stop SIP transport, stop revocation checker
- Structured JSON logging configuration
- CORS middleware (permissive for standalone use)

**Remove:** HTMX UI routes, credential explorer, admin endpoints, /verify-callee, /status, multiple template pages

##### Step 20: HTML Template (`app/templates/index.html`)

New single-page UI (~200 lines):
- Text area for PASSporT JWT input
- Text input for dossier URL (optional, extracted from JWT if present)
- "Verify" button → `POST /verify` via `fetch()`
- Result display: status badge (green/red/yellow), error list, claim tree (expandable)
- Minimal styling via inline CSS or PicoCSS CDN
- Vanilla JavaScript only — no frameworks, no HTMX
- Responsive layout

##### Step 21: Tests

8 test files (~1,000 lines total):

- `conftest.py` (~120 lines) — Ed25519 test keypair via pysodium, helper to build test JWTs, helper to build test dossier JSON, CESR dossier fixture from monorepo (`tests/fixtures/trial_dossier.json`)
- `test_header.py` (~100 lines) — Valid parse, missing fields, malformed base64, expired
- `test_passport.py` (~120 lines) — Valid JWT, wrong alg, expired, bad iat, binding validation
- `test_sip.py` (~100 lines) — Parse valid INVITE, malformed SIP, build 302/4xx responses
- `test_cache.py` (~130 lines) — LRU eviction, TTL expiry, config fingerprint invalidation, revocation status updates, deep-copy isolation
- `test_dossier.py` (~120 lines) — **CESR dossier parsing** (real fixture from monorepo trial_dossier.json), JSON array parsing, DAG build/validate, unknown format handling. At least one test per format (CESR stream, Provenant wrapper, plain JSON array)
- `test_tel.py` (~80 lines) — **Inline TEL parsing** (`_extract_tel_events` with JSON, Provenant wrapper `{"details":"..."}`, and raw CESR bracket counting), `parse_dossier_tel` with fixture data, revocation status determination (iss → ACTIVE, rev → REVOKED)
- `test_verify.py` (~200 lines) — Full pipeline: successful verification with mock dossier, signature failure, dossier fetch failure, revoked credential, unknown schema SAID (fail-closed authorization), capabilities field present in response

##### Step 22: Documentation

**README.md** (~150 lines):
- Project description (2-3 sentences)
- Quick start: Docker (`docker build -t vvp-verifier . && docker run -p 8000:8000 -p 5060:5060/udp vvp-verifier`)
- Quick start: Local (`pip install -e . && uvicorn app.main:app`)
- Configuration table with all env vars from Sprint 54 spec
- API reference: GET /, POST /verify (request/response JSON), GET /healthz
- SIP protocol: INVITE → 302 flow with example messages
- License: MIT

**ARCHITECTURE.md** (~250 lines):
- System overview diagram (SIP + HTTP dual interface)
- Module map (app/sip/, app/vvp/)
- 9-phase verification pipeline with brief descriptions
- Two-tier caching (verification result cache + dossier cache)
- Background revocation design
- Configuration model (normative vs configurable vs operational)
- **Spec compliance matrix** — full table of implemented vs excluded features with rationale (per reviewer recommendation)

**ALGORITHMS.md** (~150 lines):
- VVP-Identity header format (base64url JSON fields)
- PASSporT JWT structure (header.payload.signature)
- Ed25519 signature verification algorithm
- SAID computation (Blake3-256 with CESR encoding)
- KERI canonical serialization (field ordering rules)
- CESR encoding (derivation codes, count codes)
- ACDC credential structure (issuer, schema, attrs, edges, sigs)
- Claim tree status propagation (§3.3A precedence: INVALID > INDETERMINATE > VALID)

**SUPPORT.md** (~50 lines):
- Issue reporting (GitHub Issues link)
- VVP specification references (ATIS-1000096)
- KERI/ACDC/CESR learning resources
- Rich Connexions Ltd contact information

##### Step 23: Dockerfile

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libsodium-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY . .
EXPOSE 5060/udp 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

##### Step 24: Authorization Module (`app/vvp/authorization.py`)

**Source:** `services/verifier/app/vvp/authorization.py` (509 lines → ~300 lines)

Extract the full §5A Steps 10-11 authorization algorithm:
- `AuthorizationContext` dataclass
- `validate_authorization()` — orchestrator returning (party_authorized, tn_rights_valid) claims
- `verify_party_authorization()` — Case A (no delegation) + Case B (delegation chain walk)
- `verify_tn_rights()` — TNAlloc credential matching with E.164 range parsing
- `_walk_de_chain()` — delegation traversal (max depth 10, cycle detection)
- Helper functions for edge resolution and credential filtering

**Dependencies:** Requires `tn_utils` (E.164 parsing, range matching). Inline the essential functions from `common/vvp/utils/tn_utils.py` (~100 lines): `normalize_e164()`, `parse_tn_allocation()`, `is_subset()`, `parse_tn_ranges()`.

**Remove:** Complex logging, claim builder toString formatting

##### Step 25: Local E2E Validation (Required Gate)

Build and run the standalone verifier locally via Docker, then validate with deterministic golden-fixture comparisons:

1. **Build Docker image**: `docker build -t vvp-verifier .`
2. **Run container**: `docker run -d -p 8000:8000 -p 5060:5060/udp vvp-verifier`
3. **Health check**: `curl http://localhost:8000/healthz` — verify service up, `capabilities` block present and mandatory
4. **HTTP verification test**: POST a test PASSporT JWT + dossier URL to `http://localhost:8000/verify`, validate response structure (overall_status, claim tree, capabilities, errors)
5. **SIP verification test**: Send a crafted SIP INVITE (with Identity header) to UDP localhost:5060, verify 302 response with X-VVP-Status header
6. **Golden-fixture comparison**: Compare the `/verify` response against a checked-in golden fixture (`tests/fixtures/golden_response.json`) that was generated from the monorepo verifier during development. This ensures consistency without requiring network access to a live production endpoint. The golden fixture is version-controlled and updated only when intentional behavioral changes are made.

This is the **required gate** — all tests must pass before the sprint is complete. No external network dependencies.

##### Step 26: Azure E2E Deployment Validation (Optional)

Optionally deploy to Azure and validate against the live PBX E2E test for production confidence:

1. **Build Docker image** from the orphan branch
2. **Deploy to Azure Container Apps** as a new app (e.g., `vvp-verifier-oss`) alongside the existing verifier
3. **Configure PBX sip-verify service** to point at the standalone verifier:
   - Update `VVP_VERIFIER_URL` on the PBX to point to the standalone instance
   - This routes live SIP verification through the new codebase
4. **Run E2E test**: `./scripts/system-health-check.sh --e2e`
   - Validates signing → standalone verification → brand display
   - Compare results with the monorepo verifier (should produce identical VALID/INVALID outcomes)
5. **Restore PBX config** to point back at the production verifier after testing
6. **Document results** in the implementation notes

This is an **optional extra validation** step for production confidence. Not required for sprint completion.

### Data Flow

```
SIP INVITE (UDP 5060)           HTTP POST /verify (8000)
       │                                │
       ▼                                ▼
  SIP Parser                      FastAPI Router
       │                                │
       ▼                                ▼
  SIP Handler ─────────────────> verify()
                                    │
                        ┌───────────┤
                        ▼           ▼
                  Parse Header   Parse PASSporT
                        │           │
                        └─────┬─────┘
                              ▼
                        Bind & Verify Sig (Ed25519 Tier 1)
                              │
                        ┌─────┤ dossier cache check
                        ▼     ▼
                  Fetch Dossier (LRU+TTL cache)
                        │
                        ▼
                  Build & Validate DAG
                        │
                  ┌─────┤ result cache check
                  ▼     ▼
                  Verify ACDC Chain (cache VALID results)
                        │
                        ▼
                  Check Revocation (TEL → witness, background re-check)
                        │
                        ▼
                  Validate TN Authorization
                        │
                   ┌────┤
                   ▼    ▼
             SIP 302   JSON VerifyResponse
```

### Error Handling

ErrorCode enum (20 codes) covering all implemented features per the spec compliance matrix. Status propagation follows §3.3A precedence: INVALID > INDETERMINATE > VALID.

Each verification phase catches its own exceptions and maps them to the appropriate ErrorCode + ClaimStatus. Recoverable errors (OOBI fetch, dossier fetch, KERI resolution) produce INDETERMINATE; non-recoverable errors produce INVALID. Unhandled exceptions produce INDETERMINATE with `INTERNAL_ERROR`.

Excluded features (brand/goal/vetter/callee/SIP context) are not evaluated — they produce no claims and no errors, rather than false INDETERMINATE results. The mandatory `capabilities` dict in every `VerifyResponse` (see Step 11) makes this explicit: consumers see `"not_implemented"` for each excluded feature and can distinguish "checked and passed" from "not checked."

### Test Strategy

- Unit tests for header parser, PASSporT parser, SIP parser/builder
- Unit tests for cache operations (LRU, TTL, fingerprint, revocation updates)
- **Fixture-based tests for CESR dossier parsing** (real trial_dossier.json from monorepo) — reduces regression risk for preserved Phase 9.4 logic
- **Fixture-based tests for inline TEL parsing** (`_extract_tel_events` with JSON, Provenant wrapper, raw CESR) — validates critical revocation resolution correctness
- **Unknown schema SAID test** — verifies fail-closed authorization when credential types unrecognized
- Integration tests for full verification pipeline with mock HTTP responses
- **Capabilities field test** — verifies VerifyResponse includes capabilities block
- All tests use pysodium for real Ed25519 key generation and signing
- `pytest` runs with no network access required (all HTTP calls mocked)
- **Local E2E gate** (Docker build + HTTP/SIP smoke test) — required before completion
- **Azure E2E** (PBX integration) — optional extra validation

## Files to Create

| File | Lines (est.) | Source |
|------|-------------|--------|
| `app/__init__.py` | 1 | New |
| `app/main.py` | 300 | New (patterns from monorepo) |
| `app/config.py` | 120 | Simplified from `services/verifier/app/core/config.py` |
| `app/sip/__init__.py` | 1 | New |
| `app/sip/models.py` | 170 | From `common/vvp/sip/models.py` |
| `app/sip/parser.py` | 180 | From `common/vvp/sip/parser.py` |
| `app/sip/builder.py` | 240 | From `common/vvp/sip/builder.py` |
| `app/sip/transport.py` | 320 | From `common/vvp/sip/transport.py` |
| `app/sip/handler.py` | 150 | New (pattern from sip-verify handler) |
| `app/vvp/__init__.py` | 1 | New |
| `app/vvp/verify.py` | 500 | Simplified from `services/verifier/app/vvp/verify.py` |
| `app/vvp/header.py` | 120 | From `services/verifier/app/vvp/header.py` |
| `app/vvp/passport.py` | 250 | Simplified from `services/verifier/app/vvp/passport.py` |
| `app/vvp/signature.py` | 80 | Simplified from `services/verifier/app/vvp/keri/signature.py` |
| `app/vvp/dossier.py` | 400 | Merged from multiple sources |
| `app/vvp/acdc.py` | 500 | Merged from multiple sources |
| `app/vvp/cesr.py` | 200 | Simplified from `services/verifier/app/vvp/keri/cesr.py` |
| `app/vvp/canonical.py` | 150 | From `common/vvp/canonical/keri_canonical.py` |
| `app/vvp/schema.py` | 80 | Simplified from `common/vvp/schema/registry.py` |
| `app/vvp/models.py` | 200 | Simplified from `services/verifier/app/vvp/api_models.py` |
| `app/vvp/exceptions.py` | 60 | From `services/verifier/app/vvp/exceptions.py` |
| `app/vvp/authorization.py` | 300 | From `services/verifier/app/vvp/authorization.py` |
| `app/vvp/tel.py` | 350 | Preserved from `common/vvp/keri/tel_client.py` (inline TEL + registry OOBI) |
| `app/vvp/cache.py` | 300 | From `services/verifier/app/vvp/verification_cache.py` |
| `app/vvp/revocation.py` | 180 | From `services/verifier/app/vvp/revocation_checker.py` |
| `app/templates/index.html` | 200 | New |
| `tests/__init__.py` | 1 | New |
| `tests/conftest.py` | 100 | New |
| `tests/test_header.py` | 100 | New |
| `tests/test_passport.py` | 120 | New |
| `tests/test_sip.py` | 100 | New |
| `tests/test_cache.py` | 130 | New |
| `tests/test_dossier.py` | 120 | New (CESR + JSON fixture tests) |
| `tests/test_tel.py` | 80 | New (inline TEL parsing fixtures) |
| `tests/test_verify.py` | 200 | New (pipeline + unknown schema + capabilities) |
| `pyproject.toml` | 40 | New |
| `Dockerfile` | 15 | New |
| `.dockerignore` | 10 | New |
| `.gitignore` | 20 | New |
| `LICENSE` | 21 | New |
| `README.md` | 150 | New |
| `ARCHITECTURE.md` | 200 | New |
| `ALGORITHMS.md` | 150 | New |
| `SUPPORT.md` | 50 | New |
| `tests/fixtures/golden_response.json` | 50 | New (golden fixture from monorepo verifier) |
| **Total** | **~6,550** | **42 files** |

## Open Questions

1. **Orphan branch location:** The orphan branch `vvp-verifier` will live in the same GitHub repo for now. It can be pushed to a separate repo later. **Decided.**
2. **TN authorization scope:** Keep ACDC-based TN validation (the core VVP value) rather than simplifying to basic string matching. **Decided.**

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Import path errors after inlining | High | Low | Run pytest after each module, fix as we go |
| Missing common/ dependency discovered late | Medium | Medium | Grep for `from common.` before finishing |
| CESR simplification breaks dossier parsing | Medium | High | Test with existing monorepo test fixtures |
| Cache logic diverges from monorepo | Low | Medium | Extract with minimal changes, preserve behavior |
| Orphan branch conflicts with main | Low | Low | Orphan branch has no shared history |
| pysodium not available in Docker | Low | High | Dockerfile installs libsodium-dev explicitly |
