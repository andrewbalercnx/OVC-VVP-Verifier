## Review: Phase 2 - VVP-Identity Header Parser

**Verdict:** APPROVED

### Findings
- [Low]: Consider adding type validation for `iat`/`exp` (must be integers) and for `ppt`/`kid`/`evd` (must be non-empty strings) to prevent accepting malformed JSON types; the plan implies presence checks but doesn’t explicitly require type validation.

### Answers to Open Questions
1. OOBI validation: Defer KERI/CESR parsing to Phase 4 and treat `kid`/`evd` as opaque strings in Phase 2; avoid URL validation that could reject valid OOBI schemes.
2. Error style: Typed exceptions with error codes are the right approach; keep parser return type simple.
3. `ppt` validation: Only require presence in Phase 2; bind/validate value during PASSporT verification per §5.2.

### Additional Recommendations
- Add a test that rejects non-integer `iat`/`exp` and empty string `kid`/`evd` values, mapping to `VVP_IDENTITY_INVALID`.
