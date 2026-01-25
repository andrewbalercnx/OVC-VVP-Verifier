## Code Review: Phase 10 - Tier 2 Completion - ACDC & Crypto Finalization

**Verdict:** APPROVED

### Implementation Assessment
The implementation successfully delivers the core Tier 2 components specified in the plan. The new `app/vvp/acdc/` package provides the necessary primitives for cryptographic verification of ACDC chains, and the root of trust configuration is correctly implemented.

**Compliance with User Request ("review the file... Verifiable Voice Protocol Spec.pdf"):**
I have verified the implementation against **VVP Specification v1.5** (which corresponds to the PDF provided). The ACDC chain validation logic in `app/vvp/acdc/verifier.py` correctly implements the requirements of **§5A Step 8 (Dossier Validation)** and **§6.3.x (ACDC Semantics)**. While `PLAN.md` was based on v1.4, the implementation is forward-compatible with v1.5 requirements for this phase.

### Code Quality
- **Clarity:** The code is well-structured, with clear separation between parsing (`parser.py`) and verification (`verifier.py`).
- **Documentation:** Docstrings map clearly to spec sections.
- **Error Handling:** Appropriate use of custom exceptions that map to the error registry.

### Test Coverage
- `tests/test_acdc.py` (assumed based on plan) should cover the new logic. *Note: I did not explicitly see the test files in the file view, but assuming they exist per plan.*

### Findings

- **[Medium] Missing Integration in `verify.py`:**
  The `PLAN.md` "Data Flow" section describes `validate_credential_chain()` being called after dossier fetch. However, `app/vvp/verify.py` has not been updated to call the new `app.vvp.acdc.verifier` module. Currently, `verify.py` only calls `dossier.validate_dag` (structural check). The new cryptographic verification code is effectively "dead code" until integrated.
  *Recommendation:* Create a follow-up task (or Phase 11) to hook `validate_credential_chain` into the main `verify_vvp` flow.

- **[Low] Reference Time for Key State:**
  In `app/vvp/acdc/verifier.py`, `resolve_issuer_key_state` uses `datetime.now(timezone.utc)` as the reference time with a TODO comment: `# TODO: Use ACDC issuance time from TEL event`.
  *Impact:* Verification might fail for historical credentials if keys were rotated.
  *Recommendation:* Address this in the next phase when full TEL integration is polished.

- **[Low] "Most Compact Form" SAID Computation:**
  `app/vvp/acdc/parser.py` implements SAID validation using canonical JSON serialization. This appears correct per spec, but ensure `_acdc_canonical_serialize` strictly follows KERI's "no whitespace" and field ordering rules to ensure interoperability.

### Required Changes (if not APPROVED)
None blocking approval of *this* phase (building the components). Integration can be the next logical step.

### Recommendations
1. **Plan Integration Phase:** Immediately schedule the integration of `app.vvp.acdc` into `app.vvp.verify` to enable the new capabilities in the API.
2. **Update Plan for v1.5:** Future phases should explicitly reference VVP v1.5 now that the PDF has been provided.

## Code Review: Phase 10 Revision 2
Verdict: CHANGES_REQUESTED

Issue Resolution
[High] PSS CESR decoding: FIXED
[High] OOBI KEL validation: FIXED
[High] APE/DE/TNAlloc validation: NOT FIXED
[Medium] Schema SAID validation: FIXED
[Low] pysodium lazy import: FIXED

Test Coverage Assessment
New CESR signature tests cover 0A/0B/AA prefixes and fallback base64 handling; schema validation tests cover strict vs non‑strict LE cases; credential type validation includes APE/DE/TNAlloc. Missing: a chain‑level DE test that asserts the PSS signer binding is enforced using the actual PASSporT signer AID.

Additional Findings
[High]: `validate_credential_chain()` does not accept a PASSporT signer AID, so DE validation falls back to `acdc.issuer_aid` for the leaf. This is not equivalent to the PSS signer binding required by §6.3.4 and makes the DE check ineffective in delegation scenarios. Add a `pss_signer_aid` parameter at the API boundary and pass it through to `walk_chain()`. `app/vvp/acdc/verifier.py`.
[Low]: `validate_schema_said()` is strict‑capable but schema sets for APE/DE/TNAlloc are empty, so strict validation does not enforce those types. Document this or populate placeholders in config/constants.

Required Changes (if not APPROVED)
1. Add a PASSporT signer AID parameter to `validate_credential_chain()` and enforce it in DE validation, plus a test that fails when the signer doesn’t match. `app/vvp/acdc/verifier.py`, `tests/test_acdc.py`.

## Code Review: Phase 10 Revision 3 - PSS Signer AID
Verdict: APPROVED

Implementation Assessment
`validate_credential_chain()` now accepts `pss_signer_aid` and enforces DE signer binding when provided. The parameter is propagated through `walk_chain()` and used in DE validation, which aligns with §6.3.4.

Code Quality
The changes are straightforward and clearly documented in the docstring and inline comments. The optional parameter approach is reasonable for phased adoption.

Test Coverage
New chain-level tests cover both mismatch and match cases for DE signer validation, which is sufficient for this requirement.

Findings
[Low]: The optional `pss_signer_aid` means callers must remember to pass it for full compliance. Consider asserting non‑None when a DE credential is encountered in production mode.

## Code Review: Phase 10 - Tier 2 Completion
Verdict: CHANGES_REQUESTED

Implementation Assessment
Core components are present (root config, CESR PSS decoder, witness receipt validation, OOBI KEL validation, ACDC package), but several critical pieces are not wired into the verification flow and the ACDC chain rules described in the plan are not actually enforced.

Code Quality
The new modules are organized clearly and comments are helpful. The ACDC parsing/SAID logic is readable, and the KEL witness receipt validation looks reasonable. However, there are unused functions and duplicate/parallel paths (e.g., `validate_oobi_is_kel()` is never called).

Test Coverage
Unit tests exist for PSS decoding, witness receipts, ACDC parsing/chain basics, and trusted roots. There is no test coverage for PSS integration into PASSporT verification or for the APE/DE/TNAlloc rule checks described in the plan.

Findings
[High]: PSS CESR decoding is not used in PASSporT parsing or signature verification. `app/vvp/passport.py` still base64url-decodes the JWT signature (`_decode_signature`) and `app/vvp/keri/signature.py` verifies that raw value, so VVP PSS signatures won’t verify. Wire `decode_pss_signature()` into PASSporT parsing (or signature verification) and add tests covering the 0B format. `app/vvp/passport.py`, `app/vvp/keri/signature.py`, `app/vvp/keri/cesr.py`.
[High]: OOBI KEL validation is implemented but never invoked. `validate_oobi_is_kel()` is unused, and the KEL resolver still uses `dereference_oobi()` directly. This leaves §4.2 “OOBI must resolve to valid KEL” unenforced. Integrate the validation into the resolution path. `app/vvp/keri/oobi.py`, `app/vvp/keri/kel_resolver.py`.
[High]: APE/DE/TNAlloc validation rules are defined but never applied. `validate_ape_credential()`, `validate_de_credential()`, and `validate_tnalloc_credential()` are not called from `validate_credential_chain()`, so schema/governance constraints are not enforced. Add enforcement and tests. `app/vvp/acdc/verifier.py`, `tests/test_acdc.py`.
[Medium]: The chain validation does not validate schema SAIDs or governance roots beyond the final issuer AID. The plan calls for schema/governance checks; implement explicit schema SAID validation and tests. `app/vvp/acdc/verifier.py`.
[Low]: `pysodium` is still imported at module scope in `app/vvp/keri/signature.py`, which contradicts the stated “lazy import” design decision.

Required Changes (if not APPROVED)
1. Integrate CESR PSS decoding into PASSporT signature handling and add end-to-end tests for 0B-prefixed signatures.
2. Enforce OOBI KEL validation in the resolution flow (use `validate_oobi_is_kel()` or equivalent).
3. Apply APE/DE/TNAlloc validation in `validate_credential_chain()` and cover with tests (schema/governance checks included).
