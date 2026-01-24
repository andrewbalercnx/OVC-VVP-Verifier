# Phase 7: KERI Key State Resolution (Tier 2)

## Problem Statement

The current Tier 1 implementation extracts Ed25519 public keys directly from KERI AIDs and verifies PASSporT signatures against them. This approach has a critical limitation: it assumes the key embedded in the AID is currently valid and ignores key rotation or revocation events that may have occurred.

VVP verification requires determining key state at a specific reference time T (the `iat` timestamp). Without this capability:

1. A rotated key could still verify signatures created after the rotation
2. A revoked key could still pass verification
3. Historical verification (per §5D) is impossible
4. The verifier cannot distinguish between "key was valid at time T" and "key is valid now"

## Spec References

From `VVP_Verifier_Specification_v1.5.md`:

- **§5A Step 4** (Key State Retrieval): "Resolve issuer key state at reference time T (§5.1.1-2.4)"
- **§5C.2** (Caching): "Key state cache: AID + timestamp → Minutes (rotation-sensitive)"
- **§5D** (Historical Verification): "VVP passports can verify at arbitrary past moments using historical data"

From VVP draft §5.1.1-2.4:
- "The verifier MUST resolve the key state of the AID at reference time T"
- "Key state resolution involves fetching the Key Event Log (KEL) from witnesses"
- "The verifier MUST validate witness receipts to achieve confidence in key state"

## Current State

**Tier 1 (`app/vvp/keri/`):**
- `key_parser.py`: Parses KERI AID prefix codes (B/D) to extract 32-byte Ed25519 keys
- `signature.py`: Verifies Ed25519 signatures using pysodium
- `tel_client.py`: TEL client stub for revocation checking (Phase 9 scope)

**Vendored `keripy/`:**
- Full KERI Python implementation (not installed as pip package)
- Includes KEL parsing, eventing, signing modules
- Complex dependency tree (lmdb, falcon, hio, etc.)

**Limitations:**
- No OOBI dereferencing
- No KEL parsing
- No historical key state lookup
- No witness validation
- No key rotation detection

## Proposed Solution

### Approach

Implement a **lightweight KEL resolver** that fetches, parses, and **cryptographically validates** Key Event Logs without requiring the full keripy installation. This approach:

1. Uses HTTP to fetch KEL data from OOBI endpoints
2. Parses KEL events using a minimal event parser
3. **Validates KEL event signatures and chain continuity** (each event signed by prior key state)
4. Determines key state at time T by analyzing inception, rotation, and revocation events
5. Validates witness receipts for establishment events (using event's `toad` threshold)
6. Caches resolved key states keyed by establishment event digest

**Why this approach:**
- Avoids complex keripy dependencies (lmdb, falcon, hio)
- Reduces Docker image size
- Enables testing without full KERI infrastructure
- Sufficient for VVP verification (read-only, no key management)
- **Full cryptographic assurance through signature and chain validation**

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Full keripy integration | Complete KERI support | Heavy dependencies, complexity, Docker bloat | Overkill for read-only verification |
| External KERI agent | Isolated, maintained | Network dependency, latency, single point of failure | Adds operational complexity |
| Lightweight parser (chosen) | Simple, testable, no deps | Must maintain parser | Fits VVP read-only use case |

### Detailed Design

#### Component 1: OOBI Dereferencer

- **Purpose**: Resolve OOBI URLs to fetch KEL data
- **Location**: `app/vvp/keri/oobi.py`
- **Interface**:
  ```python
  @dataclass
  class OOBIResult:
      aid: str
      kel_data: bytes  # Raw CESR stream
      witnesses: List[str]
      error: Optional[str]

  async def dereference_oobi(oobi_url: str, timeout: float = 5.0) -> OOBIResult
  ```
- **Behavior**:
  - Fetch OOBI URL (follows redirects up to 3)
  - Require `application/json+cesr` content type (primary format)
  - Accept `application/json` only for testing (non-normative fallback)
  - Extract raw KEL stream and witness list
  - Raise `ResolutionFailedError` on network/parse failure

#### Component 2: KEL Event Parser and Validator

- **Purpose**: Parse and cryptographically validate KERI events
- **Location**: `app/vvp/keri/kel_parser.py`
- **Interface**:
  ```python
  class EventType(Enum):
      ICP = "icp"  # Inception
      ROT = "rot"  # Rotation
      IXN = "ixn"  # Interaction (ignored for key state)
      DIP = "dip"  # Delegated inception
      DRT = "drt"  # Delegated rotation

  @dataclass
  class KELEvent:
      event_type: EventType
      sequence: int
      prior_digest: str         # Reference to prior event (chain continuity)
      digest: str               # This event's digest (SAID)
      signing_keys: List[bytes] # Current signing key(s) from 'k' field
      next_keys_digest: Optional[str]  # Commitment to next keys ('n' field)
      toad: int                 # Witness threshold from event
      witnesses: List[str]      # Witness AIDs from event
      timestamp: Optional[datetime]  # From witness receipts
      signatures: List[bytes]   # Attached signatures
      witness_receipts: List[WitnessReceipt]
      raw: Dict[str, Any]

  @dataclass
  class WitnessReceipt:
      witness_aid: str
      signature: bytes
      timestamp: Optional[datetime]

  def parse_kel_stream(kel_data: bytes) -> List[KELEvent]
  def validate_kel_chain(events: List[KELEvent]) -> None  # Raises on failure
  ```
- **Behavior**:
  - Parse CESR-encoded KEL stream (primary format)
  - Extract establishment events (icp, rot, dip, drt) and interaction events
  - **Validate chain continuity**: each event's `prior_digest` MUST match previous event's `digest`
  - **Validate event signatures**: each event MUST be signed by keys from prior event (or self-signed for inception)
  - Detect delegated events (dip/drt) and raise `DelegationNotSupportedError` until Phase 7b
  - Raise `KELChainInvalidError` on chain/signature validation failure

#### Component 3: Key State Resolver

- **Purpose**: Determine key state at reference time T with full validation
- **Location**: `app/vvp/keri/kel_resolver.py`
- **Interface**:
  ```python
  @dataclass
  class KeyState:
      aid: str
      signing_keys: List[bytes]
      sequence: int                    # Establishment event sequence
      establishment_digest: str        # Digest of the establishment event
      valid_from: Optional[datetime]   # Earliest witness timestamp
      witnesses: List[str]
      toad: int                        # Witness threshold

  async def resolve_key_state(
      kid: str,
      reference_time: datetime,
      oobi_url: Optional[str] = None,
      min_witnesses: Optional[int] = None  # Uses event's toad if None
  ) -> KeyState
  ```
- **Behavior**:
  - Check cache first (keyed by AID + establishment event digest)
  - Dereference OOBI to get KEL
  - Parse and validate KEL chain (signatures + continuity)
  - Walk KEL events chronologically
  - **Find last establishment event at or before T** and return its keys
  - If no establishment event exists at/before T → raise `KeyNotYetValidError`
  - Validate witness receipts against event's `toad` threshold (or configurable minimum)
  - Cache successful resolution by establishment event digest
  - **Rotation before T is normal**: return the key that was valid at T, not an error

#### Component 4: Key State Cache

- **Purpose**: Cache resolved key states to avoid repeated OOBI lookups
- **Location**: `app/vvp/keri/cache.py`
- **Interface**:
  ```python
  @dataclass
  class CacheConfig:
      ttl_seconds: int = 300  # 5 minutes default
      max_entries: int = 1000

  class KeyStateCache:
      def get(self, aid: str, establishment_digest: str) -> Optional[KeyState]
      def get_for_time(self, aid: str, reference_time: datetime) -> Optional[KeyState]
      def put(self, key_state: KeyState) -> None
      def invalidate(self, aid: str) -> None
  ```
- **Behavior**:
  - Primary key: `(AID, establishment_digest)` - stable across time queries
  - Secondary index: `(AID, reference_time) → establishment_digest` for time-based lookups
  - LRU eviction when max_entries exceeded
  - TTL-based expiration
  - Thread-safe for async access

### Data Flow

```
PASSporT.kid (OOBI URL)
        │
        ▼
┌──────────────────┐
│ OOBI Dereferencer│ ──────► HTTP fetch from witness (CESR format)
└────────┬─────────┘
         │ OOBIResult (raw CESR)
         ▼
┌──────────────────┐
│  KEL Parser      │ ──────► Parse CESR events
└────────┬─────────┘
         │ List[KELEvent]
         ▼
┌──────────────────┐
│ Chain Validator  │ ──────► Verify signatures + chain continuity
└────────┬─────────┘
         │ Validated events
         ▼
┌──────────────────┐
│ Key State Cache  │◄────┐ Check cache by (AID, digest)
└────────┬─────────┘     │
         │ Miss          │
         ▼               │
┌──────────────────┐     │
│Key State Resolver│     │ Store by (AID, establishment_digest)
└────────┬─────────┘─────┘
         │ KeyState (keys valid at T)
         ▼
   signature.py (verify with historical key)
```

### Error Handling

| Error Condition | Error Code | Claim Status | Recovery |
|-----------------|------------|--------------|----------|
| OOBI fetch failed (network) | KERI_RESOLUTION_FAILED | INDETERMINATE | Retry with backoff |
| OOBI fetch timeout | KERI_RESOLUTION_FAILED | INDETERMINATE | Retry |
| Invalid OOBI content type | VVP_OOBI_CONTENT_INVALID | INVALID | None |
| KEL parse failed | KERI_STATE_INVALID | INVALID | None |
| KEL chain continuity broken | KERI_STATE_INVALID | INVALID | None |
| KEL event signature invalid | KERI_STATE_INVALID | INVALID | None |
| No establishment event at/before T | KERI_STATE_INVALID | INVALID | None |
| Insufficient witness receipts | KERI_RESOLUTION_FAILED | INDETERMINATE | Try more witnesses |
| Delegated event (dip/drt) detected | KERI_RESOLUTION_FAILED | INDETERMINATE | Not yet supported |

**Note**: Key rotation before T is **not an error**. The resolver returns the key that was valid at T. `KERI_STATE_INVALID` is only returned when no valid key state can be determined (e.g., reference time before inception, broken chain, invalid signatures).

### Test Strategy

1. **Unit tests for KEL parser** (`tests/test_kel_parser.py`):
   - Parse valid CESR inception event
   - Parse rotation event with key change
   - Handle malformed CESR
   - Handle missing required fields
   - Validate event SAID computation

2. **Unit tests for chain validation** (`tests/test_kel_chain.py`):
   - Validate chain continuity (prior_digest references)
   - Validate inception self-signature
   - Validate rotation signature by prior keys
   - Detect broken chain (invalid prior_digest)
   - Detect invalid event signature

3. **Unit tests for key state resolver** (`tests/test_kel_resolver.py`):
   - Find key at time T (no rotations)
   - Find key at time T (with rotation before T - returns rotated key)
   - Find key at time T (with rotation after T - returns pre-rotation key)
   - Handle reference time before inception (error)
   - Validate toad threshold enforcement

4. **Unit tests for cache** (`tests/test_kel_cache.py`):
   - Cache hit by (AID, digest)
   - Cache hit by (AID, time) via secondary index
   - Cache miss triggers resolution
   - TTL expiration
   - LRU eviction

5. **Integration tests** (`tests/test_kel_integration.py`):
   - Mock OOBI server with CESR responses
   - End-to-end key state resolution
   - Delegated event detection (returns INDETERMINATE)

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/keri/oobi.py` | Create | OOBI dereferencing |
| `app/vvp/keri/kel_parser.py` | Create | KEL event parsing + chain validation |
| `app/vvp/keri/kel_resolver.py` | Create | Key state at time T |
| `app/vvp/keri/cache.py` | Create | Key state caching |
| `app/vvp/keri/signature.py` | Modify | Use resolved key state |
| `app/vvp/keri/exceptions.py` | Modify | Add new exception types |
| `tests/test_kel_parser.py` | Create | KEL parser tests |
| `tests/test_kel_chain.py` | Create | Chain validation tests |
| `tests/test_kel_resolver.py` | Create | Resolver tests |
| `tests/test_kel_cache.py` | Create | Cache tests |
| `tests/test_kel_integration.py` | Create | Integration tests |

## Resolved Questions (per Reviewer)

1. **Witness threshold**: Use the event's `toad` field if present; otherwise use a configurable minimum with production default ≥ quorum of current witnesses. Avoid fixed "1" default beyond dev.

2. **CESR vs JSON**: CESR is the primary supported format per `application/json+cesr`. JSON is allowed only for tests or clearly marked non-normative fallback.

3. **Delegation events**: Detect `dip`/`drt` and return INDETERMINATE with `DelegationNotSupportedError` until delegated resolution is implemented in a future phase.

4. **Cache granularity**: Cache by `(AID, establishment_event_digest)` with a secondary index `(AID, reference_time) → event_digest`. Avoid rounding timestamps.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| CESR parsing complexity | Medium | High | Use keripy CESR parsing as reference; comprehensive test vectors |
| Signature validation complexity | Medium | High | Reuse existing Ed25519 verification; test against keripy-generated events |
| Witness unavailability | Medium | Medium | Fall back to cached state with warning |
| Performance degradation | Low | Medium | Aggressive caching by event digest; async fetches |
| Edge cases in KEL walk | Medium | Medium | Comprehensive test vectors; clear error classification |

---

## Revision 1 (Response to CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [High] No KEL event signature validation and chain continuity checks | Added explicit chain validation (Component 2), signature verification against prior key state, and `validate_kel_chain()` function |
| [High] "Key rotated before T → KERI_STATE_INVALID" incorrect | Fixed: rotation before T is normal, resolver returns key valid at T. Error only if no establishment event at/before T |
| [Medium] Cache key rounding to minute risks incorrect results | Changed cache key to `(AID, establishment_event_digest)` with secondary time index |

### Additional Improvements

1. Added `WitnessReceipt` dataclass for structured receipt handling
2. Added `DelegationNotSupportedError` for dip/drt detection
3. Added separate test file for chain validation (`test_kel_chain.py`)
4. Clarified `KERI_RESOLUTION_FAILED` vs `KERI_STATE_INVALID` semantics in error table
5. Added `valid_from` timestamp to KeyState for temporal ordering

---

## Reviewer Prompt (Revision 1)

```
## Plan Review Request: Phase 7 - KERI Key State Resolution (Revision 1)

You are the Reviewer in a pair programming workflow. This is a re-review after addressing your previous CHANGES_REQUESTED feedback.

### Documents to Review

1. `PLAN.md` - The revised plan with "Revision 1" section documenting fixes

### Changes Made Since Last Review

| Finding | Resolution |
|---------|------------|
| [High] No KEL signature/chain validation | Added explicit chain validation, signature verification against prior keys |
| [High] Rotation before T incorrectly treated as error | Fixed: return key valid at T, only error if no establishment event at/before T |
| [Medium] Cache rounding risks | Changed to (AID, establishment_digest) with secondary time index |

Additional improvements:
- WitnessReceipt dataclass for structured receipts
- DelegationNotSupportedError for dip/drt detection
- Separate test file for chain validation
- Clarified error code semantics

### Your Task

1. Verify the required changes have been correctly addressed
2. Confirm chain validation and signature verification are now explicit in the design
3. Confirm the key-at-T logic no longer treats rotation as an error
4. Confirm cache keying strategy avoids timestamp rounding
5. Provide verdict and feedback in `REVIEW.md`

### Response Format

Write your response to `REVIEW.md` using this structure:

## Plan Review: Phase 7 - KERI Key State Resolution (Revision 1)

**Verdict:** APPROVED | CHANGES_REQUESTED

### Required Changes Verification
[Confirm each required change was properly addressed]

### Additional Improvements Assessment
[Evaluation of the additional changes made]

### Findings
- [High]: Critical issue that blocks approval
- [Medium]: Important issue that should be addressed
- [Low]: Suggestion for improvement (optional)

### Required Changes (if CHANGES_REQUESTED)
1. [Specific change required]

### Final Recommendations
- [Optional improvements or future considerations]
```

---

## Implementation Notes

### Deviations from Plan

1. **Cache time index**: Added a `reference_time` parameter to `cache.put()` to also index by the query time, enabling cache hits on subsequent queries for the same AID and reference time.

2. **Timezone handling**: Added `_normalize_datetime()` and `_compare_datetimes()` helpers to handle both timezone-aware and naive datetimes, since KEL timestamps may include timezone info (Z suffix) while query times may be naive.

3. **CESR parsing**: Full CESR binary parsing is stubbed with a TODO - the implementation currently supports JSON-encoded KEL for testing. CESR parsing will be completed when real KERI infrastructure is available for testing.

### Implementation Details

- Used `httpx` for async HTTP in OOBI dereferencer (consistent with existing codebase)
- Signature verification reuses existing `pysodium` integration from Tier 1
- Cache uses `asyncio.Lock` for thread safety in async context
- All datetime comparisons normalized to UTC to avoid timezone comparison errors

### Test Results

```
94 passed (Phase 7 tests)
365 passed, 2 skipped (full test suite)
```

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `app/vvp/keri/exceptions.py` | +48 | Added KELChainInvalidError, KeyNotYetValidError, DelegationNotSupportedError, OOBIContentInvalidError |
| `app/vvp/keri/cache.py` | +210 | New key state cache with LRU eviction and TTL |
| `app/vvp/keri/kel_parser.py` | +380 | KEL event parser with chain validation |
| `app/vvp/keri/oobi.py` | +180 | OOBI dereferencer for fetching KEL data |
| `app/vvp/keri/kel_resolver.py` | +330 | Key state resolver at reference time T |
| `app/vvp/keri/signature.py` | +50 | Added verify_passport_signature_tier2 |
| `app/vvp/keri/__init__.py` | +30 | Updated exports for Tier 2 |
| `tests/test_kel_parser.py` | +190 | KEL parser unit tests |
| `tests/test_kel_chain.py` | +280 | Chain validation tests |
| `tests/test_kel_cache.py` | +280 | Cache behavior tests |
| `tests/test_kel_resolver.py` | +290 | Resolver tests |
| `tests/test_kel_integration.py` | +280 | End-to-end integration tests |

---

## Implementation Revision 1 (Response to Code Review CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [High] CESR parsing not implemented but expected | Added explicit CESR detection that returns clear `ResolutionFailedError` explaining JSON-only is supported. Updated docstrings to clarify limitation. |
| [High] Signature canonicalization doesn't match KERI | Added extensive warning in `_compute_signing_input()` documenting that JSON sorted-key canonicalization is test-only and won't work with real KERI events. |
| [Medium] SAID validation missing | Added `_validate_event_said()` function and integrated into `validate_kel_chain()`. Defaults to disabled since test fixtures use placeholder digests. |
| [Medium] Missing timestamps use latest state | Changed to raise `ResolutionFailedError` (INDETERMINATE) when rotations lack timestamps, since we cannot determine temporal validity. Inception-only KELs without timestamps still work. |
| [Low] Timezone handling in signature.py | Changed `datetime.fromtimestamp(iat)` to `datetime.fromtimestamp(iat, tz=timezone.utc)` for consistent UTC handling. |

### Test Updates

- Renamed `test_events_without_timestamps_use_sequence` to `test_events_without_timestamps_raises_indeterminate`
- Added `test_inception_only_without_timestamp_succeeds` to verify inception-only KELs work

### Test Results (Revision 1)

```
95 passed (Phase 7 tests)
366 passed, 2 skipped (full test suite)
```

---

## Implementation Revision 2 (Response to Code Review CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [High] CESR still not supported - functional blocker | Per reviewer recommendation, added feature flag `TIER2_KEL_RESOLUTION_ENABLED` to gate Tier 2 as TEST-ONLY. Default is `False`. |
| [High] Signature canonicalization still test-only | Added feature flag gating. Tier 2 now explicitly fails with clear error when flag is disabled. |
| [Medium] SAID validation disabled by default | Documented in code; feature flag now makes Tier 2 limitations explicit. |
| [Medium] Rotation without timestamps test coverage | Verified `test_events_without_timestamps_raises_indeterminate` exists at line 229 of test_kel_resolver.py and correctly tests INDETERMINATE behavior. |

### Implementation Details

1. **Feature Flag in config.py**:
   Added `TIER2_KEL_RESOLUTION_ENABLED: bool = False` with extensive documentation explaining:
   - JSON-only: CESR binary format NOT supported
   - Signature canonicalization uses JSON sorted-keys, NOT KERI-compliant Blake3
   - SAID validation disabled by default
   - Conclusion: Tier 2 ONLY works with synthetic test fixtures

2. **Feature Gate in kel_resolver.py**:
   `resolve_key_state()` checks `TIER2_KEL_RESOLUTION_ENABLED` first and raises `ResolutionFailedError` with clear message when disabled. Added `_allow_test_mode` parameter to bypass gate for tests.

3. **Feature Gate in signature.py**:
   `verify_passport_signature_tier2()` also checks the flag and has `_allow_test_mode` parameter for testing.

4. **Test Updates**:
   - All 14 tests calling `resolve_key_state()` updated to pass `_allow_test_mode=True`
   - Added `TestFeatureFlag` class with 2 tests verifying gate behavior:
     - `test_tier2_disabled_by_default`: Verifies resolution fails when flag disabled
     - `test_tier2_allowed_with_test_mode`: Verifies `_allow_test_mode=True` bypasses gate

### Files Changed (Revision 2)

| File | Change |
|------|--------|
| `app/core/config.py` | Added `TIER2_KEL_RESOLUTION_ENABLED = False` with documentation |
| `app/vvp/keri/kel_resolver.py` | Added feature gate check, `_allow_test_mode` parameter |
| `app/vvp/keri/signature.py` | Added feature gate check, `_allow_test_mode` parameter, updated docstring |
| `tests/test_kel_resolver.py` | Updated 2 tests with `_allow_test_mode=True` |
| `tests/test_kel_integration.py` | Updated 12 tests with `_allow_test_mode=True`, added `TestFeatureFlag` class |

### Test Results (Revision 2)

```
97 passed (Phase 7 tests)
368 passed, 2 skipped (full test suite)
```
