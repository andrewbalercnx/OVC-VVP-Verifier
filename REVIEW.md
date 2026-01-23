## Review: Phase 3 - PASSporT JWT Verification

**Verdict:** CHANGES_REQUESTED

### Findings
- [High]: `validate_passport_binding` allows PASSporT `exp` omission unconditionally, but v1.4 §5.2A requires treating PASSporT as expired when VVP‑Identity `exp` is present and PASSporT `exp` is absent (default reject). Since `VVPIdentity.exp` is always populated (computed in Phase 2), the current implementation never triggers this rejection and is spec‑noncompliant. `app/vvp/passport.py:118` `app/vvp/passport.py:153` `app/vvp/header.py:86`
- [High]: The tests codify the above noncompliance: `test_max_age_within_limit_no_exp` expects a valid outcome when PASSporT `exp` is absent and VVP‑Identity has `exp`. Per §5.2A default policy, this should be rejected unless explicitly configured to allow omission. `tests/test_passport.py:742` `app/Documentation/VVP_Verifier_Specification_v1.4_FINAL.md:352`
- [Medium]: There is no way to distinguish whether VVP‑Identity `exp` was explicitly provided vs computed default. §5.2A’s rule depends on this distinction, so Phase 2/3 needs an explicit flag (e.g., `exp_provided: bool`) carried in `VVPIdentity`. Without it, binding can’t follow spec. `app/vvp/header.py:20`

### Answers to Open Questions
1. `typ` validation: Ignoring `typ` is consistent with v1.4 (no requirement). 
2. Binding failure error code: Mapping binding violations to `PASSPORT_PARSE_FAILED` is reasonable; keep `PASSPORT_EXPIRED` for actual expiry policy checks.
3. `call-reason` mapping: `call-reason` → `call_reason` with raw payload preservation is fine.

### Additional Recommendations
- Add a specific test that PASSporT `exp` omission is rejected when VVP‑Identity `exp` was explicitly provided (default behavior), and a separate test for the “configured to allow omission” case.
- Consider adding a small note in `PassportPayload`/`VVPIdentity` to carry explicit `exp` presence to support §5.2A.
