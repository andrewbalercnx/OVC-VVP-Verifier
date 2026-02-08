# Sprint 51: Verification Result Caching

## Revision History

- **v1**: Initial design — cache complete VerifyResponse by dossier URL
- **v2**: Revised per Codex review (CHANGES_REQUESTED) — cache only dossier-derived immutable artifacts; re-evaluate all per-request checks on every call
- **v3**: Revised per second Codex review (CHANGES_REQUESTED) — stale revocation → INDETERMINATE; dossier artifact TTL; chain_claim evidence constraints; DossierCache interaction documented
- **v4**: Revised per third Codex review (CHANGES_REQUESTED) — compound cache key `(dossier_url, pss_signer_aid)` to handle DE binding and witness URL variation; only cache VALID chain results (transient failures not cached)
- **v5**: Revised per fourth Codex review (CHANGES_REQUESTED) — revocation checker updates all signer variants for a URL; chain errors cached in `CachedDossierVerification`; structural vs transient INVALID clarified; `pss_signer_aid=None` entries not cached
- **v6**: Revised per fifth Codex review (CHANGES_REQUESTED) — deep-copy on cache read to prevent cross-request mutation; config fingerprint included in cache versioning for trusted roots/operator severity
- **v7**: Revised per sixth Codex review (CHANGES_REQUESTED) — restrict caching to VALID only (eliminates structural/transient INVALID classification ambiguity); `revocation_pending` justified with backward-compatibility note; error-merging strategy specified; `RevocationStatus` moved to verifier-local module; benchmark CI exclusion noted
- **v8**: Revised per seventh Codex review (CHANGES_REQUESTED) — explicit §5.1.1-2.9/§5C.2 compliance justification for cached revocation; schema registry inputs documented as SAID-determined (not runtime-configurable); `dossier_acdcs` deep-copied on cache read
- **v9**: Revised per eighth Codex review (CHANGES_REQUESTED) — cache key expanded from `pss_signer_aid` to full PASSporT `kid` (captures witness URL variation); config fingerprint expanded to include all validation-affecting switches
- **v10**: Revised per ninth Codex review (CHANGES_REQUESTED) — `revocation_last_checked` atomically updated for all kid variants on background check completion; `dossier_claim_evidence` added to deep-copy list
- **v11**: Revised per tenth Codex review (CHANGES_REQUESTED) — `issuer_identities` removed from cache (recomputed per-request from cached `dossier_acdcs` + current well-known registry); chain_claim evidence request-independence confirmed

## Problem Statement

The current dossier cache (`DossierCache`) only caches the parsed DAG and raw bytes, saving the HTTP fetch + parse on cache hit (~500-2000ms). However, every verification request still performs all expensive downstream operations regardless of cache status:

| Operation | Typical Latency | Immutable? | Currently Cached? |
|-----------|-----------------|------------|-------------------|
| HTTP fetch + CESR parse | 500-2000ms | N/A | Yes (dossier cache) |
| ACDC chain validation (schema resolution, trust root walk) | 500-3000ms | Yes (SAID-addressed) | No |
| ACDC signature verification (KEL fetch, key state resolution) | 200-1000ms | Yes (SAID-addressed) | No |
| Revocation checking (TEL queries) | 200-2000ms | **No** (mutable) | No (synchronous!) |
| Authorization validation | 5-20ms | Per-request | No |

**Result:** A dossier cache hit saves ~1-2s of fetch time but still incurs ~1-5s of chain/signature/revocation work.

**Key Insight:** All KERI ACDCs are formally non-repudiable. The credential chain structure, ACDC signatures, and schema validations are immutable once resolved (SAID-addressed). Only revocation status can change. The expensive operations (Phases 5.5 + 9 = 700-5000ms) can be cached by dossier URL, while per-request checks (PASSporT, SIP context, authorization, brand, business logic) are re-evaluated every time.

**Additional Finding:** The existing `DossierCache.put()` background revocation check is never triggered because `verify.py` line 902 calls `put()` without passing `chain_info`, making the fire-and-forget revocation task dead code.

## Spec References

- §5.1.1-2.7: Dossier Cache Check — verifier MAY cache parsed dossiers
- §5C.2: Freshness policy for cached data
- §5.1.1-2.9: Revocation status check for all credentials
- §3.3A: Status propagation through claim tree
- §5.1/§5.2: Per-request PASSporT validation (binding, expiry, signature)
- §4.4: Per-request SIP context alignment

**Revocation caching compliance (§5.1.1-2.9 + §5C.2):**

§5.1.1-2.9 requires the verifier to perform a "revocation status check for all credentials." This requirement is satisfied on cache hits as follows:
- **Fresh cached revocation data** (within `VVP_REVOCATION_RECHECK_INTERVAL`): The revocation status was obtained from a TEL query during a previous verification or background re-check. This constitutes a valid "revocation status check" — the spec requires checking status, not mandating a synchronous TEL query per request. The cached result represents the outcome of a completed check.
- **Stale cached revocation data** (exceeds `VVP_REVOCATION_RECHECK_INTERVAL`): The verifier returns `revocation_clear = INDETERMINATE` with evidence "revocation_data_stale". This is the correct §5C.2 freshness response — when the verifier cannot assure revocation data is fresh, it MUST NOT claim VALID. INDETERMINATE signals "insufficient or unverifiable evidence" per §3.2, which is the appropriate outcome.
- **No revocation data yet** (first cache hit before background check completes): Returns `revocation_clear = INDETERMINATE` with evidence "revocation_check_pending". Same §3.2 semantics.
- **Net effect**: Every verification response either includes a conclusive revocation check result (fresh data → VALID/INVALID) or explicitly signals uncertainty (stale/pending → INDETERMINATE). §5.1.1-2.9 is satisfied because the verifier always evaluates revocation status; it never silently omits the check.

## Current State

- `DossierCache` (in `common/common/vvp/dossier/cache.py`) caches raw dossier + DAG by URL with TTL
- `verify_vvp()` (in `services/verifier/app/vvp/verify.py`) orchestrates the full 11-phase verification pipeline every time
- Existing background revocation infrastructure in `DossierCache` is dead code (chain_info never passed)
- No caching of chain validation or ACDC signature verification results

## Proposed Solution

### Approach: Cache Dossier-Derived Verification Artifacts

Cache **dossier-derived verification artifacts** (chain validation, ACDC signature verification, issuer identities) keyed by the compound key `(dossier_url, passport_kid)`. On cache hit, skip the expensive Phases 5, 5.5, and 9, but **always re-evaluate per-request checks**: PASSporT parse/bind/signature (Phase 2-4), authorization (Phase 10-11), SIP context (Phase 13), brand (Phase 11b), business logic (Phase 11c), and vetter constraints (Sprint 40).

**WHY a compound cache key:** Phase 5.5 chain validation uses `pss_signer_aid` (extracted from PASSporT kid) for DE signer binding validation (§6.3.4) and derives witness base URLs from the full `kid` for external SAID resolution. Two different `kid` values can map to the same AID but different witness endpoints, potentially changing resolution outcomes. The compound key `(dossier_url, passport_kid)` captures both the signer identity AND the resolution path, ensuring cached results are only reused when the full input context matches. In practice, a given signer consistently uses the same `kid`, so hit rates remain high.

**WHY this approach:**
1. **Correctness**: PASSporT validation (§5.1/§5.2), SIP context alignment (§4.4), and authorization are always re-evaluated. Chain validation is cached per-kid to correctly handle DE binding variation (§6.3.4) and witness URL variation in external SAID resolution.
2. **Performance**: The cached phases (chain validation 500-3000ms + ACDC signatures 200-1000ms + revocation 200-2000ms) represent 900-6000ms. Per-request phases (PASSporT signature 200-1000ms + other fast checks ~50ms) are 250-1050ms. Cache hit latency: **250-1050ms** (down from 1700-7000ms total).
3. **Simplicity**: Compound key adds minimal complexity. High hit rate for the common case (same kid + same dossier). Different kids for the same dossier are rare but handled correctly.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Cache complete VerifyResponse by dossier URL | Sub-100ms cache hit | Skips per-request PASSporT/context validation; violates §5.1/§5.2 | **Rejected per Codex review** — conflates immutable and per-request results |
| Cache by hash of all request inputs | Preserves per-request correctness | Low hit rate (different PASSporTs → different hashes); still needs temporal revalidation | Over-complicated for marginal benefit |
| Increase dossier cache TTL only | Simple | Doesn't address chain/signature re-verification | Saves only fetch time |
| External cache (Redis) | Survives restarts | Infrastructure dependency | Over-engineered for single-instance |

### Detailed Design

#### Immutable vs Per-Request Classification

This classification drives what is cached vs re-evaluated:

| Phase | Operation | Immutable? | Cached? |
|-------|-----------|------------|---------|
| 2 | VVP-Identity header parse | Per-request | No — always re-evaluated |
| 3 | PASSporT parse + binding | Per-request | No — always re-evaluated |
| 4 | PASSporT KERI signature | Per-request | No — always re-evaluated |
| 5 | Dossier fetch + parse | Yes (SAID-addressed) | Yes (existing DossierCache) |
| 5.5 | ACDC chain validation | Yes (SAID-addressed), but uses per-request `kid` for DE binding + witness URLs | **Yes — NEW** (compound key includes full `kid`; VALID results only) |
| 5.5b | ACDC signature verification | Yes (SAID-addressed) | **Yes — NEW** |
| 9 | Revocation checking | Mutable | **Yes — background async** |
| 10-11 | Authorization | Per-request (depends on PASSporT orig.tn) | No — always re-evaluated |
| 13 | SIP context alignment | Per-request (depends on SIP context) | No — always re-evaluated |
| 11b | Brand verification | Per-request (depends on PASSporT card) | No — always re-evaluated |
| 11c | Business logic | Per-request (depends on PASSporT goal) | No — always re-evaluated |
| 40 | Vetter constraints | Per-request (depends on PASSporT TNs) | No — always re-evaluated |

#### Component 1: RevocationStatus Enum

- **Purpose**: Three-state revocation status for each credential in a cached result
- **Location**: `services/verifier/app/vvp/verification_cache.py` (co-located with the verification cache that uses it, not in `common/` since it's verifier-specific and not needed by issuer or other consumers)
- **Values**: `UNDEFINED`, `UNREVOKED`, `REVOKED`

```python
from enum import Enum

class RevocationStatus(Enum):
    UNDEFINED = "UNDEFINED"
    UNREVOKED = "UNREVOKED"
    REVOKED = "REVOKED"
```

#### Component 2: CachedDossierVerification

- **Purpose**: Stores immutable dossier-derived verification artifacts
- **Location**: `services/verifier/app/vvp/verification_cache.py`
- **Cache key**: Compound `(dossier_url, passport_kid)` — Phase 5.5 chain validation extracts `pss_signer_aid` from the `kid` for DE signer binding (§6.3.4) and derives witness base URLs from the same `kid` for external SAID resolution. Two different `kid` values can map to the same AID but different witness endpoints, so the full `kid` must be part of the key (not just the extracted AID).
- **Fields**:
  - `dossier_url: str` — Part of compound key (from VVP-Identity evd field)
  - `passport_kid: str` — Part of compound key (full PASSporT kid header value). Entry not cached if kid is None or empty.
  - `dag: DossierDAG` — Parsed credential graph
  - `raw_dossier: bytes` — Raw dossier bytes (for inline TEL parsing during revocation re-check)
  - `dossier_acdcs: Dict[str, ACDC]` — Converted ACDCs (used by authorization/brand/vetter on cache hit)
  - `chain_claim: ClaimNode` — Immutable chain_verified claim node with all evidence
  - `chain_errors: List[ErrorDetail]` — Errors from chain validation (Phase 5.5), preserved on cache hit so API responses include them
  - `acdc_signatures_verified: bool` — Whether ACDC signatures passed in Phase 5.5b
  - `has_variant_limitations: bool` — Whether dossier contains compact/partial ACDCs
  - `dossier_claim_evidence: List[str]` — Evidence strings from dossier validation
  - ~~`issuer_identities`~~ **Removed from cache** — recomputed per-request from `dossier_acdcs` + current well-known registry (see "Issuer identity recomputation" below)
  - `contained_saids: FrozenSet[str]` — All credential SAIDs in dossier (immutable)
  - `credential_revocation_status: Dict[str, RevocationStatus]` — Per-credential revocation
  - `revocation_last_checked: Optional[float]` — Unix timestamp of last background check
  - `created_at: float` — Unix timestamp when first cached
  - `cache_version: int` — For invalidation on code changes (see versioning policy below)
  - `config_fingerprint: str` — Hash of verification-relevant config (trusted roots, operator severity, external SAID resolution). Mismatch on read → cache miss.

**Design decision:** We store `dag`, `raw_dossier`, and `dossier_acdcs` because:
- `dag` + `raw_dossier` are needed for background revocation re-checking
- `dossier_acdcs` is needed for per-request authorization, brand, vetter validation on cache hit
- `chain_claim` is the immutable claim node that gets wired into the new response's claim tree
- `chain_errors` preserves chain-related `ErrorDetail` objects so cache hits emit the same errors as full pipeline runs (prevents API behavioral regression)

**Issuer identity recomputation:** `issuer_identities` is NOT cached because it depends on the well-known AIDs registry (`WELLKNOWN_AIDS_FILE`), which can change at runtime (operator updates). Instead, on cache hits, `issuer_identities` is recomputed per-request by calling `resolve_issuer_identities(cached.dossier_acdcs)` — this is a fast in-memory operation (~1-5ms) that reads credential attributes from the cached ACDCs and applies the current well-known AID fallback registry. This ensures identity results always reflect the latest operator configuration.

**chain_claim evidence constraint:** The cached `chain_claim` MUST contain only dossier-derived, request-independent evidence. Reviewing the existing code in `verify.py` Phase 5.5, the chain_claim is built exclusively from:
- `validate_credential_chain()` results (ACDC chain walk against trusted roots)
- `verify_acdc_signature()` results (CESR signature verification)
- Leaf credential counts and chain validation status strings

None of these depend on per-request inputs (PASSporT, SIP context, etc.). The `chain_claim` evidence strings are: `leaves=N`, `chain_valid:SAID...,root=AID...`, `chain_indeterminate:SAID...`, `sig_valid:SAID...`, `variant_limitations=true`. All are deterministic functions of dossier content.

**Confirmed request-independence of chain_claim evidence:** Reviewing `verify.py` Phase 5.5 (lines 918-1158), the `chain_claim` (`chain_verified` ClaimBuilder) accumulates evidence exclusively from: (a) `validate_credential_chain()` — outputs chain walk results based on DAG content and trusted roots, (b) `verify_acdc_signature()` — outputs signature verification based on CESR content, (c) leaf counting and chain status strings. No PASSporT-derived data (kid, orig, dest), SIP context, authorization decisions, or other per-request inputs are injected into chain_claim evidence. The `pss_signer_aid` is used as an INPUT to the chain validation function (for DE binding), but does not appear in the chain_claim evidence strings — it affects the validation OUTCOME (VALID/INVALID), not the evidence text. Since the compound cache key includes the full `kid` (which determines `pss_signer_aid`), the cached chain_claim is correct for any request with the same kid.

The compound cache key `(dossier_url, pss_signer_aid)` ensures DE binding correctness without relying on evidence-string filtering. Since `pss_signer_aid` is part of the key, different signers get separate cache entries, and the chain_claim for each entry is correct for that signer's DE binding and witness URLs.

**Missing `kid` handling:** If the PASSporT has no `kid` header (None or empty), the chain validation result is NOT cached, because: (a) a missing kid indicates an issue with the PASSporT that prevents proper DE binding and witness resolution, and (b) an empty-keyed entry could be incorrectly reused by a subsequent request with a valid kid. The full pipeline runs every time when kid is absent.

#### Component 3: VerificationResultCache

- **Purpose**: In-memory LRU cache of dossier-derived verification artifacts
- **Location**: `services/verifier/app/vvp/verification_cache.py`
- **Interface**:
  ```python
  CACHE_VERSION = 1  # Bump when cached data format or verification logic changes

  class VerificationResultCache:
      async def get(self, dossier_url: str, passport_kid: str) -> Optional[CachedDossierVerification]
      async def put(self, result: CachedDossierVerification) -> None  # key derived from result fields
      async def update_revocation(self, dossier_url: str, passport_kid: str, credential_said: str, status: RevocationStatus) -> None
      async def update_revocation_all_for_url(self, dossier_url: str, credential_said: str, status: RevocationStatus) -> None  # update all kid variants
      async def invalidate(self, dossier_url: str, passport_kid: str) -> None
      async def invalidate_all_for_url(self, dossier_url: str) -> None  # evict all kid variants
      def metrics(self) -> VerificationCacheMetrics
  ```
- **Key structure**: Internally, the cache is keyed by `(dossier_url, passport_kid)` tuples. `get()` requires both parts. `invalidate_all_for_url()` evicts all entries for a given dossier URL (across all kids). In practice, a given signer consistently uses the same kid and dossier URL, so the compound key does not reduce hit rates.
- **TTL**: Entries expire after `VVP_VERIFICATION_CACHE_TTL` seconds (default: 3600s = 1 hour). Although ACDC content is SAID-addressed and immutable, dossier URLs are not guaranteed to be immutable — the same URL could serve different content over time (e.g., credential re-issuance). The TTL ensures stale chain/signature artifacts are eventually evicted. This aligns with §5C.2 freshness policy. The 1-hour default is longer than the existing 300s DossierCache TTL because chain validation results change less frequently than raw dossier content, but shorter than indefinite to handle URL content changes. Revocation freshness is enforced separately via `VVP_REVOCATION_RECHECK_INTERVAL`.
- **Cache-eligibility policy**: Only cache chain validation results where `chain_claim.status == VALID`. Neither INVALID nor INDETERMINATE results are cached:
  - **VALID**: Cache. Immutable SAID-addressed results backed by successful trust root verification, schema validation, and ACDC signature verification. Won't change on retry.
  - **INVALID / INDETERMINATE**: Do NOT cache. Although some INVALID results represent deterministic structural failures (untrusted root, broken chain), others could theoretically arise from transient resolution failures that happen to map to INVALID. Rather than maintaining a fragile classification of structural vs transient INVALID, we conservatively skip caching all non-VALID results. The performance impact is negligible: INVALID/INDETERMINATE chains represent misconfigured or error-state credentials, which are rare in production.
- **Size**: Max 200 entries (configurable via `VVP_VERIFICATION_CACHE_MAX_ENTRIES`)
- **Eviction**: LRU when at capacity (same pattern as `DossierCache`)
- **Thread safety**: `asyncio.Lock` (same pattern as `DossierCache`)
- **Version check**: `get()` compares `entry.cache_version` against `CACHE_VERSION` constant. On mismatch, the entry is evicted and `None` is returned.
- **Deep-copy on read**: `get()` returns a deep copy of mutable fields via `copy.deepcopy()` to prevent cross-request mutation. Deep-copied fields:
  - `chain_claim` — downstream phases mutate claim nodes in-place (status propagation, evidence accumulation, child wiring)
  - `chain_errors` — error lists could be appended to during response construction
  - `credential_revocation_status` — modified by `update_revocation`
  - `dossier_acdcs` — although currently read-only in cache-hit flows (authorization, brand, vetter), downstream phases could theoretically add annotations or normalize ACDC objects. Defensive deep-copy prevents any future mutation from corrupting cached state.
  - `dossier_claim_evidence` — evidence list that cache-hit flow appends to (e.g., `cache_hit:dossier_verification`); must be independent per request to avoid cross-request contamination

  The following fields are returned by reference for efficiency (immutable or structurally not modified):
  - `dag` — DossierDAG is only read during background revocation re-check
  - `raw_dossier` — bytes object (immutable in Python)
  - `contained_saids` — frozenset (immutable)

  Note: `issuer_identities` is no longer cached (recomputed per-request from `dossier_acdcs`).
- **Config fingerprint**: The cache stores a `config_fingerprint: str` computed at cache-put time from verification-relevant config values: `TRUSTED_ROOT_AIDS`, `OPERATOR_VIOLATION_SEVERITY`, and `EXTERNAL_SAID_RESOLUTION_ENABLED`. On `get()`, the stored fingerprint is compared against the current fingerprint; mismatches are treated as cache misses (entry evicted). This handles runtime config changes (e.g., trusted root rotation) without requiring service restart. The fingerprint is a deterministic hash of sorted config values.

```python
@dataclass
class VerificationCacheMetrics:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    version_mismatches: int = 0
    config_mismatches: int = 0
    revocation_checks: int = 0
    revocations_found: int = 0
```

**Cache Versioning Policy:**
- `CACHE_VERSION` is a module-level integer constant in `verification_cache.py`, initially `1`
- It is set in `CachedDossierVerification.cache_version` at creation time
- `get()` compares the stored version against the current `CACHE_VERSION`; mismatches are treated as cache misses and the entry is evicted
- **When to bump**: any change to chain validation logic, ACDC signature verification, claim tree structure, or CachedDossierVerification fields
- The cache is also cleared on service restart (in-memory only), so version bumps are a safety net for hot-reload scenarios

**Config Fingerprint Policy:**
- `config_fingerprint` is computed via `hashlib.sha256` over a deterministic serialization of all validation-affecting config values:
  - `sorted(TRUSTED_ROOT_AIDS)` — trust root set for chain walk
  - `OPERATOR_VIOLATION_SEVERITY` — edge operator violation handling
  - `EXTERNAL_SAID_RESOLUTION_ENABLED` — external SAID resolution toggle
  - `SCHEMA_VALIDATION_STRICT` — strict vs lenient schema validation mode
  - `TIER2_KEL_RESOLUTION_ENABLED` — Tier 2 KEL resolution toggle (affects signature verification)
  - `EXTERNAL_SAID_MAX_DEPTH` — max depth for external SAID traversal (affects chain completeness)
- Stored in each `CachedDossierVerification` at creation time
- `get()` computes the current fingerprint and compares; mismatch → cache miss (entry evicted), increments `config_mismatches` metric
- This handles the scenario where an operator rotates trusted roots or changes violation severity without restarting the service
- Helper function `compute_config_fingerprint() -> str` in `verification_cache.py`

**Schema registry inputs are NOT included in the config fingerprint** because:
- Schema validation is determined by the schema SAIDs referenced in each ACDC credential
- Schema SAIDs are content-addressed (SAID = self-addressing identifier) — the same SAID always resolves to the same schema content regardless of registry URL
- The `SCHEMA_REGISTRY_URL` config only affects *where* schemas are fetched from, not *which* schemas are valid
- Schema "pinning" (e.g., WebOfTrust schema repo version) is baked into credential content at issuance time, not configurable at runtime by the verifier
- Therefore, schema registry configuration changes do not affect the correctness of cached chain validation results for any given dossier URL

#### Component 4: BackgroundRevocationChecker

- **Purpose**: Single background task that periodically re-checks revocation status for cached results
- **Location**: `services/verifier/app/vvp/revocation_checker.py`
- **Behavior**:
  1. On cache put: enqueue dossier URL for revocation checking
  2. Single worker task consumes from `asyncio.Queue` (enforced by semaphore)
  3. Deduplication via a `Set[str]` of pending dossier URLs — won't re-enqueue if already pending. Keyed by dossier URL only (not compound key) because revocation is a per-credential property, not per-signer.
  4. For each item: call `check_dossier_revocations()` with cached DAG/raw/OOBI
  5. **Update ALL kid variants** for the dossier URL in the cache — revocation status is per-credential (per-SAID), independent of which kid presented the dossier. Uses `VerificationResultCache.update_revocation_all_for_url(dossier_url, credential_said, status)` to atomically update all `(dossier_url, *)` entries. **Simultaneously updates `revocation_last_checked` to `time.time()` for all variants** — this is done inside the same lock acquisition as the status update, ensuring atomic freshness bookkeeping. After this, all cached entries for the URL have consistent freshness timestamps.
  6. On revocation detected: marks credential REVOKED in all kid variants, logs event
  7. Periodic re-check: dossier URLs where `revocation_last_checked` > `VVP_REVOCATION_RECHECK_INTERVAL` are re-enqueued on cache hit
- **Queue**: `asyncio.Queue` with deduplication set (keyed by dossier URL)
- **Concurrency**: Single checker task (configurable via `VVP_REVOCATION_CHECK_CONCURRENCY`)

```python
class BackgroundRevocationChecker:
    def __init__(self, cache: VerificationResultCache, recheck_interval: float = 300.0):
        self._cache = cache
        self._recheck_interval = recheck_interval
        self._queue: asyncio.Queue = asyncio.Queue()
        self._pending: Set[str] = set()
        self._semaphore = asyncio.Semaphore(1)
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def enqueue(self, dossier_url: str) -> None:
        """Enqueue dossier URL for revocation checking (deduplicates by URL). Updates all signer variants."""

    async def start(self) -> None:
        """Start the background worker task."""

    async def stop(self) -> None:
        """Gracefully stop the worker."""

    async def _worker(self) -> None:
        """Main worker loop: consume from queue, check revocations."""
```

#### Component 5: Modified verify_vvp() Flow

- **Location**: `services/verifier/app/vvp/verify.py`
- **Changes**: After PASSporT signature verification (Phase 4), check the dossier verification cache using the compound key `(dossier_url, passport.header.kid)`. On hit, skip Phases 5, 5.5, and 9 but continue with all per-request phases.

**New flow on cache hit (compound key matches):**

1. Phase 2: Parse VVP-Identity header — **always** (fail → early INVALID return)
2. Phase 3: Parse + bind PASSporT — **always** (needed to extract `kid` for cache key)
3. Phase 4: Verify PASSporT KERI signature — **always**
4. Check `VerificationResultCache.get(vvp_identity.evd, passport.header.kid)` (kid is the full PASSporT kid header value)
6. Phase 5: **SKIP** dossier fetch/parse — use `cached.dag` and `cached.dossier_acdcs`
7. Phase 5.5: **SKIP** chain validation + ACDC signatures — use `cached.chain_claim` and `cached.chain_errors`
8. Phase 9: **SKIP** synchronous revocation — build `revocation_clear` claim from `cached.credential_revocation_status` with **freshness enforcement** per §5C.2:
   - **Freshness check first**: If `revocation_last_checked` is None or older than `VVP_REVOCATION_RECHECK_INTERVAL` seconds, the revocation data is **stale**
   - **Stale revocation data** → `revocation_clear` = INDETERMINATE with evidence "revocation_data_stale" regardless of cached UNREVOKED/REVOKED values. Enqueue background re-check.
   - **Fresh + all UNREVOKED** → `revocation_clear` = VALID
   - **Fresh + any REVOKED** → `revocation_clear` = INVALID (add CREDENTIAL_REVOKED error)
   - **Fresh + any UNDEFINED** → `revocation_clear` = INDETERMINATE with evidence "revocation_check_pending"
   - This ensures stale UNREVOKED status never produces a VALID claim, aligning with §5.1.1-2.9 and §5C.2
9. Phase 10-11: Run authorization — **always** (uses cached `dossier_acdcs` + current PASSporT)
10. Phase 13: Run SIP context alignment — **always**
11. Phase 11b: Run brand verification — **always** (uses cached `dossier_acdcs` + current PASSporT card)
12. Phase 11c: Run business logic — **always** (uses current PASSporT goal)
13. Sprint 40: Run vetter constraints — **always** (uses cached `dossier_acdcs` + current PASSporT TNs)
14. Build claim tree with cached chain_claim + fresh per-request claims
15. Propagate status and derive overall
16. Return response with `revocation_pending` flag if any credential is UNDEFINED
17. Add evidence `cache_hit:dossier_verification` to dossier_claim

**New flow on cache miss:**

1. Full verification pipeline as today (Phases 2-13, Sprint 40)
2. After verification completes, extract dossier-derived artifacts:
   - `chain_claim` node from the built claim tree
   - `passport_kid` from PASSporT header
   - `dag`, `raw_dossier`, `dossier_acdcs`, `has_variant_limitations`
   - `issuer_identities`, `contained_saids`
   - Per-credential revocation status from the synchronous check result
3. **Only cache if ALL conditions are met**:
   - `passport_kid` is not None/empty (kid must be present — see "Missing kid handling" above)
   - `chain_claim.status == VALID` (only VALID results are cached; INVALID and INDETERMINATE are not — see cache-eligibility policy above)
4. Store `CachedDossierVerification` in cache (keyed by `dossier_url` + `passport_kid`), including `chain_errors` (typically empty for VALID chains, but preserved for completeness)
5. Enqueue background revocation re-check for ongoing freshness
6. Return response as before

**Error-merging strategy on cache hit:**

The `VerifyResponse.errors` list accumulates errors from multiple phases in sequence. On a cache hit, errors are merged as follows:
- **Phase 2-4 errors** (VVP-Identity parse, PASSporT parse/bind, PASSporT signature): Always fresh — appended first, as today
- **Phase 5.5 errors** (`cached.chain_errors`): Deep-copied from cache and appended in the same position they would occupy in the full pipeline. Since only VALID chain results are cached, `chain_errors` will typically be empty for cache hits. However, they are preserved for edge cases where a VALID chain still produces warnings.
- **Phase 9 errors** (revocation): Generated fresh from cached revocation status — appended in Phase 9 position
- **Phase 10-13+ errors** (authorization, SIP context, brand, business logic, vetter): Always fresh — appended in their respective positions

This produces the same error ordering as a full pipeline run. No duplication occurs because each phase contributes distinct `ErrorCode` values, and cached errors occupy their original phase position. The deep-copy of `chain_errors` ensures cached error objects are not mutated by downstream processing.

**Implementation approach:** Rather than duplicating the per-request phases, we'll introduce a helper function and early-return pattern in `verify_vvp()`. The existing function structure (sequential phases) makes it natural to insert a branch after Phase 4 (PASSporT signature verification) — once we have the signer AID — that checks the cache and, on hit, jumps to Phase 10 (authorization) with the cached artifacts.

Specifically, the code change is:
```python
# After Phase 4 (PASSporT signature verified), before Phase 5:
evd_url = vvp_identity.evd
passport_kid = passport.header.kid if passport else None

cached_dossier_verification = None
if VERIFICATION_CACHE_ENABLED and passport_kid:
    cached_dossier_verification = await verification_cache.get(evd_url, passport_kid)

# Then in Phase 5/5.5/9 sections, check for cached_dossier_verification:
if cached_dossier_verification is not None:
    # Use cached chain_claim, dag, dossier_acdcs
    # Build revocation_clear from cached revocation status
    # Skip fetch, parse, chain validation, ACDC sig verification, revocation
else:
    # Full pipeline as today
    # After completion, only cache if:
    #   1. passport_kid is not None/empty
    #   2. chain_claim.status == VALID (only VALID results cached)
    # Cache chain_errors alongside chain_claim for API consistency
```

#### Component 6: VerifyResponse Enrichment

- **Location**: `services/verifier/app/vvp/api_models.py`
- **Change**: Add optional `revocation_pending` field to `VerifyResponse`

```python
class VerifyResponse(BaseModel):
    # ... existing fields ...
    revocation_pending: bool = False
```

**Interaction with existing semantics:** When `revocation_pending` is True:
- `revocation_clear` claim will be INDETERMINATE with evidence "revocation_check_pending"
- This is consistent with the existing INDETERMINATE semantics (§3.2: "Insufficient or unverifiable evidence")
- The `revocation_pending` field is a convenience for API consumers to distinguish "not yet checked" from "check failed"
- Not redundant with existing warnings — ToIP warnings are for spec compliance, not cache state

**Backward compatibility:** The `revocation_pending` field is:
- **Optional** with default `False` — existing clients that don't read it see no change
- **Additive only** — no existing fields are removed or renamed
- **Pydantic `BaseModel` default behavior** — new optional fields with defaults are backward-compatible in JSON serialization (old clients ignore unknown fields)
- **Not spec-mandated** — it's an implementation convenience, not a normative requirement. The formal verification result semantics are carried entirely by the claim tree status (VALID/INVALID/INDETERMINATE) and evidence strings. The field simply surfaces cache state metadata.
- **Precedent**: Prior API additions (e.g., `issuer_identities` in Sprint 38, `sip_context` in Sprint 42) followed the same additive pattern without breaking clients.

### Data Flow

```
Request arrives
    │
    ▼
Phase 2: Parse VVP-Identity header
    ├─ FAIL: Return INVALID immediately
    │
    ▼
Phase 3: Parse + bind PASSporT (always — kid needed for cache key)
Phase 4: Verify PASSporT KERI signature (always)
    │
    ▼
Check VerificationResultCache by (dossier_url, passport_kid)
    │
    ├─ HIT (cached entry for this kid):
    │   │
    │   ├─ Phase 5/5.5: SKIP — use cached dag, chain_claim, chain_errors, dossier_acdcs
    │   ├─ Recompute issuer_identities from cached dossier_acdcs + current well-known registry
    │   ├─ Phase 9: Build revocation_clear from cached revocation status
    │   │           + Stale data → INDETERMINATE (per §5C.2)
    │   │           + Enqueue re-check if stale
    │   ├─ Phase 10-11: Authorization (always, uses cached dossier_acdcs)
    │   ├─ Phase 13: SIP context (always)
    │   ├─ Phase 11b: Brand (always, uses cached dossier_acdcs)
    │   ├─ Phase 11c: Business logic (always)
    │   ├─ Sprint 40: Vetter constraints (always, uses cached dossier_acdcs)
    │   ├─ Build claim tree + propagate status
    │   └─ Return (~250-1050ms, saving 900-6000ms)
    │
    └─ MISS (no cache entry for this kid):
        │
        ├─ Full verification pipeline (all phases)
        ├─ Extract dossier-derived artifacts + passport_kid + chain_errors
        ├─ Guard: passport_kid must not be None/empty
        ├─ If chain_claim.status == VALID:
        │   ├─ Store in VerificationResultCache (keyed by dossier_url + passport_kid)
        │   └─ Enqueue background revocation check (by dossier_url, updates all signer variants)
        ├─ If chain_claim.status != VALID (INVALID or INDETERMINATE):
        │   └─ Do NOT cache (conservative: avoid ambiguity between structural and transient failures)
        └─ Return full result
```

### Interaction with Existing DossierCache

The new `VerificationResultCache` and the existing `DossierCache` serve complementary purposes:

| Cache | Keys | Stores | TTL | Purpose |
|-------|------|--------|-----|---------|
| `DossierCache` (existing) | Dossier URL | Raw bytes + DAG | 300s | Skip HTTP fetch + CESR parse on repeated requests |
| `VerificationResultCache` (new) | (Dossier URL, passport_kid) | Chain claim + ACDC sigs + identities + revocation | 3600s | Skip chain validation + ACDC sig verification + synchronous revocation |

**Interaction:** On a verification cache hit, the DossierCache is not consulted (the verification cache already stores `dag` and `raw_dossier`). On a verification cache miss, the DossierCache is still checked first (existing behavior in Phase 5). This means the DossierCache continues to provide value for its 300s window even before chain validation results are cached.

**Retiring dead code:** The existing `DossierCache.start_background_revocation_check()` and related `_do_revocation_check()`, `_revocation_tasks` infrastructure is dead code (never invoked from the verification path). This sprint does NOT remove it to avoid scope creep, but a follow-up task should be logged to retire it once the new `BackgroundRevocationChecker` is proven. The new checker operates on the `VerificationResultCache`, not the `DossierCache`.

### Error Handling

| Scenario | Handling |
|----------|----------|
| Cache version mismatch | `get()` returns None, evicts stale entry, increments `version_mismatches` metric |
| Config fingerprint mismatch | `get()` returns None, evicts stale entry, increments `config_mismatches` metric |
| Cross-request mutation | `get()` deep-copies `chain_claim`, `chain_errors`, `credential_revocation_status`, `dossier_acdcs`, `dossier_claim_evidence`; immutable fields (`dag`, `raw_dossier`, `contained_saids`) returned by reference; `issuer_identities` recomputed per-request |
| Background revocation check failure | Keep credential as UNDEFINED, retry on next interval; log error |
| Memory pressure | LRU eviction ensures bounded memory usage |
| Race between cache read and revocation update | `asyncio.Lock` prevents concurrent access |
| Service restart | In-memory cache cleared automatically; first requests do full pipeline |

### Test Strategy

1. **Unit tests** (`test_verification_cache.py`):
   - `VerificationResultCache`: get/put/eviction/metrics/invalidate
   - `CachedDossierVerification`: construction with all fields including `passport_kid`
   - `RevocationStatus` enum values
   - Compound key: same dossier_url with different passport_kid → separate entries
   - Compound key: same dossier_url with same passport_kid → cache hit
   - Compound key: passport_kid=None → not cached (guard enforced)
   - `invalidate_all_for_url`: evicts all kid variants for a URL
   - Cache version mismatch: put with version 1, bump CACHE_VERSION to 2, verify get returns None
   - Config fingerprint mismatch: change TRUSTED_ROOT_AIDS after cache put, verify get returns None
   - Deep-copy safety: get() returns independent copies — mutating returned chain_claim/chain_errors does not affect cached entries
   - Deep-copy safety: concurrent get() calls return independent objects
   - LRU eviction order
   - `update_revocation` updates correct credential for correct (url, kid) pair

2. **Unit tests** (`test_revocation_checker.py`):
   - `BackgroundRevocationChecker`: enqueue/dedup/start/stop
   - Single-task enforcement (semaphore)
   - Revocation detection updates ALL kid variants for the dossier URL
   - Dedup is by dossier URL only (not compound key)
   - Re-enqueue on stale interval
   - Graceful shutdown

3. **Integration tests** (`test_verify_caching.py`):
   - First call: full pipeline, stores in cache
   - Second call (same signer): cache hit, skips chain/signature/revocation but re-runs PASSporT/auth/context
   - Different PASSporT kid for same dossier: cache miss (different compound key), full pipeline, separate cache entry
   - Same kid for same dossier: cache hit regardless of different PASSporT content (PASSporT validated fresh)
   - Transient failure: chain validation returns INDETERMINATE due to network error → result NOT cached, next call retries full pipeline
   - Structural failure: chain validation returns INVALID (untrusted root) → result NOT cached (VALID-only policy), next call retries full pipeline
   - Only VALID cached: verify only chain_claim.status == VALID entries are stored
   - passport_kid=None/empty: result NOT cached, next call retries full pipeline
   - Revocation status transitions: UNDEFINED → UNREVOKED, UNDEFINED → REVOKED
   - Revocation update propagation: revocation check updates all kid variants for same dossier URL
   - Stale revocation data on cache hit → INDETERMINATE (not VALID), enqueue re-check
   - `revocation_pending` flag set correctly on cache hit with UNDEFINED status
   - Cache disabled via feature flag: all calls go through full pipeline
   - Cache version mismatch: bump version, verify full pipeline re-runs
   - Cache TTL: entries expire after configured TTL, verify miss after expiry
   - Error ordering: cache hit response errors are in same order as full pipeline (Phase 2-4 → Phase 5.5 → Phase 9 → Phase 10+)
   - Config fingerprint: change trusted roots after cache put, verify cache miss

4. **Benchmark** (`benchmarks/test_cache_performance.py`):
   - Measure first-call vs second-call response time
   - Verify significant improvement on cache hit (target: >50% reduction)
   - **CI exclusion**: Benchmarks are placed in `services/verifier/benchmarks/` (not `tests/`), which is outside the default pytest discovery path configured in `pytest.ini`. They are run manually or via explicit path: `./scripts/run-tests.sh benchmarks/`

5. **Mutation safety tests** (in `test_verification_cache.py`):
   - Verify that mutating a returned `chain_claim` does not affect subsequent `get()` calls
   - Verify that mutating returned `chain_errors` list does not affect cached data
   - Verify that mutating returned `dossier_acdcs` dict does not affect cached data
   - Verify that mutating returned `dossier_claim_evidence` list does not affect cached data
   - Verify that concurrent `get()` calls return independent objects
   - Verify that `revocation_last_checked` is updated atomically for all kid variants after background check
   - Verify that stale detection flips correctly: stale before check → fresh after check for all kid variants

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/verifier/app/vvp/verification_cache.py` | Create | VerificationResultCache + CachedDossierVerification + RevocationStatus + metrics + CACHE_VERSION |
| `services/verifier/app/vvp/revocation_checker.py` | Create | BackgroundRevocationChecker |
| `services/verifier/app/vvp/verify.py` | Modify | Cache-first verification flow (skip 5/5.5/9 on hit, always run per-request phases) |
| `services/verifier/app/vvp/api_models.py` | Modify | Add revocation_pending to VerifyResponse |
| `services/verifier/app/core/config.py` | Modify | Add VVP_VERIFICATION_CACHE_* configuration |
| `services/verifier/app/main.py` | Modify | Start/stop BackgroundRevocationChecker on app lifecycle |
| `services/verifier/tests/test_verification_cache.py` | Create | Cache unit tests |
| `services/verifier/tests/test_revocation_checker.py` | Create | Background checker tests |
| `services/verifier/tests/test_verify_caching.py` | Create | Integration tests for cached flow |
| `services/verifier/benchmarks/test_cache_performance.py` | Create | Before/after benchmark |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_VERIFICATION_CACHE_ENABLED` | `true` | Feature flag to enable/disable |
| `VVP_VERIFICATION_CACHE_MAX_ENTRIES` | `200` | Max cached dossier verification artifacts |
| `VVP_VERIFICATION_CACHE_TTL` | `3600` | TTL for cached artifacts in seconds (handles URL content changes) |
| `VVP_REVOCATION_RECHECK_INTERVAL` | `300` | Seconds between background revocation re-checks; stale data → INDETERMINATE |
| `VVP_REVOCATION_CHECK_CONCURRENCY` | `1` | Max concurrent revocation check tasks |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Stale revocation status served | Medium | High | Background checker + configurable refresh interval; UNDEFINED → INDETERMINATE clearly indicated via `revocation_pending` |
| Memory growth from cached artifacts | Low | Medium | LRU eviction + configurable max entries; metrics endpoint for monitoring |
| Code upgrade invalidates cached results | Low | Low | `CACHE_VERSION` constant + version check in `get()`; cache cleared on restart |
| Race between cache read and revocation update | Low | Low | asyncio.Lock; atomic status transitions |
| Different PASSporTs for same dossier URL | Expected | None | Per-request phases always re-evaluated; only dossier-derived artifacts cached |
| Different kids for same dossier URL | Low | Low | Compound key `(dossier_url, passport_kid)` ensures correct DE binding and witness URL per kid; separate cache entries created |
| Non-VALID results cached incorrectly | N/A | Avoided | Only VALID chain results are cached; INVALID and INDETERMINATE are never cached, eliminating structural/transient classification ambiguity |

---

## Implementation Notes

### Deviations from Plan
- **Benchmark deferred**: The `benchmarks/test_cache_performance.py` file was not created. Benchmarking requires a real dossier + real KERI infrastructure running, which goes beyond unit/integration test scope. The cache hit path is verified by integration tests confirming expensive mocks are NOT called on second invocation.
- **`check_dossier_revocations` mock**: Integration tests mock this function (async) to avoid real HTTP calls to witness nodes during Phase 9 revocation checking. The unit tests in `test_verification_cache.py` and `test_background_revocation_checker.py` already cover revocation status transitions in isolation.

### Implementation Details
- Cache-first flow inserted at line ~838 in `verify_vvp()`, between Phase 4 (PASSporT signature) and Phase 5 (dossier fetch).
- Used conditional guards (`and not _verification_cache_hit`) on existing if/elif conditions rather than wrapping 350+ lines in a new block — minimal diff, same semantics.
- Variable initialization for Phase 5 defaults (`raw_dossier`, `dag`, `acdc_signatures`, `has_variant_limitations`) moved before the cache check so cache hit can override them.
- On cache hit, `chain_node` set directly from cached `ClaimNode` (deep-copied by `get()`). On cache miss, built from `ClaimBuilder` in Phase 6 (guarded by `if not _verification_cache_hit:`).
- Test isolation required `reset_verification_cache()` and `reset_revocation_checker()` functions added to both `conftest.py` and `vectors/conftest.py` (the latter overrides the parent's autouse fixture).

### Test Results
- 1803 tests passed, 0 failures, 9 skipped
- New tests: 51 (16 integration + 28 cache unit + 7 revocation checker unit)

### Files Changed
| File | Lines | Summary |
|------|-------|---------|
| `services/verifier/app/vvp/verification_cache.py` | +378 | New module: cache, metrics, config fingerprint, singleton |
| `services/verifier/app/vvp/revocation_checker.py` | +187 | New module: background revocation worker, singleton |
| `services/verifier/app/vvp/verify.py` | +160 | Cache-first flow, cache storage, conditional guards |
| `services/verifier/app/vvp/api_models.py` | +1 | `revocation_pending` field on `VerifyResponse` |
| `services/verifier/app/core/config.py` | +16 | 4 cache config constants |
| `services/verifier/app/main.py` | +15 | Lifespan context manager for background worker |
| `services/verifier/tests/conftest.py` | +6 | Reset verification cache + revocation checker |
| `services/verifier/tests/vectors/conftest.py` | +6 | Same resets in vectors conftest |
| `services/verifier/tests/test_verification_cache.py` | +465 | 28 unit tests for cache |
| `services/verifier/tests/test_background_revocation_checker.py` | +155 | 7 unit tests for revocation checker |
| `services/verifier/tests/test_verify_caching.py` | +357 | 16 integration tests |

## Measurable Success Criteria

| Metric | Before (Current) | Target (Sprint 51) |
|--------|-------------------|---------------------|
| Second read latency (same dossier) | 1.7-7s (full pipeline) | 250-1050ms (cache hit, skip chain/sig/revocation) |
| Time saved on cache hit | 0s (no effective caching) | 900-6000ms (chain + sig + revocation) |
| Revocation freshness | Synchronous per-request | Background, <300s staleness |
| Memory overhead | ~5MB (dossier DAGs only) | ~25MB (DAGs + chain claims + ACDC maps) |
| Spec compliance | N/A | All per-request checks always run |

## Open Questions

None — the reviewer's feedback has been fully incorporated. The revised design cleanly separates dossier-derived immutable artifacts from per-request validation.
