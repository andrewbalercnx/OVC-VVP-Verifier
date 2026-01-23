## Review: Phase 3 - PASSporT JWT Verification

**Verdict:** APPROVED

### Findings
- [Low]: Consider adding a note that `exp > iat` and exp/iat drift failures are treated as `PASSPORT_PARSE_FAILED` because they’re binding/protocol violations, to avoid confusion with expiry policy errors in downstream handling.

### Answers to Open Questions
1. `typ` validation: Ignoring `typ` is acceptable since v1.4 doesn’t mandate it; keep it untouched unless you explicitly add local policy.
2. Binding failure error code: Using `PASSPORT_PARSE_FAILED` for ppt/kid/iat/exp binding mismatches is consistent with §4.2A and keeps `PASSPORT_EXPIRED` reserved for true expiry policy failures.
3. `call-reason` mapping: `call-reason` → `call_reason` with raw payload retention is good.

### Additional Recommendations
- None required; plan aligns with v1.4 §§5.0–5.4 and cleanly separates spec‑mandated vs local policy checks.
