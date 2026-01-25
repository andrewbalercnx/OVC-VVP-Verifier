# Plan: CESR Parsing + KERI Canonicalization (Tier 2 Enablement)

## Goal
Enable Tier 2 KEL resolution against real OOBIs by implementing CESR stream parsing, KERI‑compliant canonicalization/serialization, and SAID validation. This removes the current JSON‑only, test‑mode limitation and allows `TIER2_KEL_RESOLUTION_ENABLED` to be safely enabled in production.

## Scope
- CESR parsing of KEL streams (events + attachments)
- KERI canonicalization for signing input
- SAID computation using “most compact form”
- Signature verification against canonical bytes
- OOBI content-type handling for CESR vs JSON test mode
- Tests with real CESR fixtures
- Documentation updates and feature‑flag transition plan

Out of scope:
- Full KERI agent integration
- Delegated event resolution (dip/drt) beyond detection and INDETERMINATE

---

## Workstream 1: CESR Stream Parsing

### Deliverables
- `app/vvp/keri/cesr.py` (new) or extend `kel_parser.py` with CESR parsing

### Tasks
1. Implement a CESR tokenizer that iterates a byte stream and extracts:
   - Event payload (JSON)
   - Controller signatures
   - Witness receipts
2. Support common attachment types needed for KEL validation:
   - Indexed controller signatures (0A/0B/0C...)
   - Witness receipts (`rcts`)
3. Return a structured result:
   - `event_raw: dict`
   - `signatures: List[bytes]`
   - `witness_receipts: List[WitnessReceipt]`
   - `metadata` for debugging (count codes, lengths)

### Tests
- `tests/test_cesr_parser.py`:
  - Valid CESR KEL stream parses into correct event + attachments
  - Truncated/invalid count codes raise `ResolutionFailedError`

---

## Workstream 2: KERI Canonicalization / Serialization

### Deliverables
- `app/vvp/keri/keri_canonical.py` (new)

### Tasks
1. Implement `canonical_event_bytes(event_raw) -> bytes` using KERI label ordering by event type.
2. Ensure serialization matches KERI expectations:
   - No whitespace
   - Stable field ordering per event type
3. Replace `_compute_signing_input()` to use canonical bytes (not JSON sorted keys).

### Tests
- `tests/test_canonicalization.py`:
  - Canonical bytes match known fixtures for icp/rot/ixn

---

## Workstream 3: SAID Computation (Most Compact Form)

### Deliverables
- Update `compute_said()` to use KERI canonical bytes
- Enable `_validate_event_said()` by default for CESR inputs

### Tasks
1. Build “most compact form” with placeholder `d`.
2. Hash canonical bytes (blake3‑256) and encode with derivation code.
3. Compare computed SAID to event’s `d` and raise on mismatch.

### Tests
- `tests/test_said.py`:
  - Computed SAID matches known KERI vectors for icp/rot events
  - Invalid `d` triggers `KELChainInvalidError`

---

## Workstream 4: Chain Validation Against Canonical Bytes

### Deliverables
- Update `validate_kel_chain()` to:
  - Use canonical bytes for signature validation
  - Require SAID validation for CESR inputs

### Tasks
1. Verify inception signatures against its own keys.
2. Verify rotation signatures against prior establishment keys.
3. Ensure `prior_digest` chain continuity still enforced.

### Tests
- Extend `tests/test_kel_chain.py` with CESR fixtures:
  - Valid chain passes
  - Wrong signature fails
  - SAID mismatch fails

---

## Workstream 5: OOBI Content Handling

### Deliverables
- Update `oobi.py` + `kel_parser.py` integration

### Tasks
1. If `content-type` is `application/json+cesr`, parse via CESR path.
2. If `application/json`, allow only when `_allow_test_mode=True`.
3. Keep JSON path explicitly non‑compliant for production.

### Tests
- `tests/test_kel_integration.py`:
  - CESR content-type uses CESR parser
  - JSON content-type requires test mode

---

## Workstream 6: Feature Flag Transition

### Deliverables
- Update `TIER2_KEL_RESOLUTION_ENABLED` documentation
- Remove “test‑only” warnings once CESR path passes

### Tasks
1. Add readiness checklist in docs:
   - CESR parser complete
   - Canonicalization complete
   - SAID validation enabled
   - CESR integration tests passing
2. Flip flag to `True` only when checklist passes.

---

## Workstream 7: Fixtures and Validation Strategy

### Deliverables
- CESR fixtures generated with keripy (or trusted KERI tools)

### Tasks
1. Generate fixture sets:
   - Inception only
   - Rotation with timestamps
   - Witness receipts + toad threshold
2. Store fixtures under `tests/fixtures/keri/`.
3. Use fixtures in parser, canonicalization, chain validation, and integration tests.

---

## Suggested Implementation Order
1. CESR tokenizer + event extraction
2. Canonicalization + signing input
3. SAID computation + validation
4. Chain validation on CESR fixtures
5. Update OOBI handling
6. Run integration tests and enable feature flag

---

## Risks and Mitigations
- CESR complexity: Use keripy outputs as authoritative fixtures.
- Canonicalization mismatch: Validate against known vectors before enabling Tier 2.
- False invalids: Keep JSON test path for unit tests but never for production.

---

## Exit Criteria
- CESR KEL parsing passes fixtures
- Canonicalization produces correct signing bytes
- SAID validation enabled and passing
- `verify_passport_signature_tier2()` works with real CESR inputs
- Feature flag can be safely enabled for production
