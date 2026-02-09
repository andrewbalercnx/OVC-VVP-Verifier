# Sprint 54: Dossier Verification Performance — Characterization & Optimization

## Problem Statement

A single `verify_vvp()` call involves multiple sequential and parallel external HTTP calls, CPU-bound parsing, and in-memory caching operations. There is no instrumentation to identify where time is actually spent, which external endpoints are slow or dead, and which phases dominate latency. Without characterization data we cannot make evidence-based optimization decisions.

Additionally, several external endpoints are queried speculatively (e.g., schema registries, witness TEL endpoints, GLEIF discovery). When these endpoints are unreachable or slow, they silently add seconds of timeout to every verification request — potentially dominating total latency even though their failure is non-fatal.

## Goals

1. **Characterize** — Add structured timing instrumentation to every phase of `verify_vvp()` so we can measure real-world latency distribution.
2. **Surface dead endpoints** — Detect and log external endpoints that consistently fail or timeout, and expose this via a health/metrics endpoint.
3. **Optimize hot paths** — Apply targeted code-level optimizations to the highest-impact areas identified during the exploration phase.
4. **Background slow checks** — Move non-blocking external calls (revocation, schema resolution) out of the critical path where possible.

## Spec References

- §9: Verification orchestration (phases 2–13)
- §5C.2: Freshness policy (cache TTLs)
- §6.1B: Dossier fetch constraints (timeout 5s, size 1MB)
- §5.1.1-2.9: Revocation checking

## Current State

### Verification Pipeline Phases (verify.py)

Each `verify_vvp()` call runs these phases sequentially:

| Phase | Name | Type | External Calls | Timeout |
|-------|------|------|---------------|---------|
| 2 | VVP-Identity Parse | CPU | None | — |
| 3 | PASSporT Parse + Bind | CPU | None | — |
| Cache | Verification cache lookup | CPU/Mem | None | — |
| 4 | KERI Signature (Tier 2) | **I/O** | OOBI fetch → KEL parse → key state | 5s |
| 5 | Dossier Fetch + Parse | **I/O** | HTTP GET dossier URL | 5s |
| 5.5 | ACDC Chain Validation | **I/O+CPU** | Schema fetch (per credential) + External SAID resolution | 5s per source |
| 9 | Revocation Check | **I/O** | TEL queries to 6+ witnesses | 10s per witness |
| 10-11 | Authorization + Context | CPU | None | — |
| 11 | Brand + Business Logic | CPU | None | — |
| 40 | Vetter Constraints | CPU | None | — |

### External HTTP Call Inventory

| Call Site | File | Endpoint Pattern | Timeout | Failure Mode | Impact |
|-----------|------|-----------------|---------|-------------|--------|
| Dossier fetch | `common/vvp/dossier/fetch.py` | `{evd_url}` (user-supplied) | 5s | FetchError → INDETERMINATE | Blocks Phase 5 |
| OOBI dereference | `keri/oobi.py:81` | `{kid_oobi_url}` | 5s | ResolutionFailedError → INDETERMINATE | Blocks Phase 4 |
| Schema fetch (legacy) | `acdc/schema_fetcher.py:67` | `schema.gleif.org/{said}`, `schema.provenant.net/{said}` | 10s | ResolutionFailedError → INDETERMINATE | Per-credential in Phase 5.5 |
| Schema resolve (new) | `acdc/schema_resolver.py:411` | Same registries + GitHub raw | 5s | None → INDETERMINATE | Per-credential in Phase 5.5 |
| TEL via OOBI | `keri/tel_client.py:291` | `{witness}/query?typ=tel&vcid={said}` | 10s | ERROR → tries next witness | Per-credential in Phase 9 |
| TEL via witness | `keri/tel_client.py:344` | `{witness}/query?typ=tel&vcid={said}`, `{witness}/tels/{said}` | 10s | ERROR → tries next witness | Per-credential in Phase 9 |
| GLEIF witness discovery | `keri/witness_pool.py` | `gleif.org/.well-known/keri/oobi/{root_aid}` | implicit | Degrades to Provenant-only | Lazy, first-use |
| External SAID resolution | `keri/credential_resolver.py` | `{witness}/credentials/{said}` | 5s | None → INDETERMINATE | Per-missing-edge in Phase 5.5 |

### Key Observations

1. **New `httpx.AsyncClient` per call** — Every external HTTP call creates and tears down a fresh `httpx.AsyncClient`. This means no TCP connection reuse, no HTTP/2 multiplexing, and repeated TLS handshakes. In the worst case (schema + TEL + OOBI), a single verification creates 10+ separate TCP connections.

2. **TEL queries are sequential per witness** — `check_revocation()` in `tel_client.py:250` iterates witnesses sequentially (`for witness_url in witness_urls`), creating a new `httpx.AsyncClient` per witness per credential. With 6 Provenant witnesses at 10s timeout, worst case is 60s+ for one credential.

3. **Schema registries may be unreachable** — `schema.gleif.org` and `schema.provenant.net` are external third-party endpoints. If they're down, each schema fetch adds 5-10s of timeout per credential. The embedded schema store mitigates this for known schemas, but unknown schemas still hit the network.

4. **No metrics on endpoint health** — There's no tracking of which endpoints consistently fail. A dead witness eats its full timeout before being skipped.

5. **Revocation is on the critical path** — Phase 9 runs inline before the response. For cache misses this means TEL queries block the response. The Sprint 51 verification cache helps for repeat requests, but first-request latency is still dominated by TEL queries.

6. **`compute_config_fingerprint()` per cache get** — Every verification cache lookup computes a SHA-256 hash of 6 config values that never change at runtime.

7. **O(n) LRU eviction** — Both `VerificationResultCache` and `KeyStateCache` use `list.remove()` for LRU tracking, which is O(n) per access.

8. **Lazy imports in hot loops** — `pysodium`, `blake3`, `base64`, `math`, `re` are imported inside functions called per-signature, per-event, per-SAID.

## Proposed Solution

### Approach

A phased approach: **instrument first**, then **optimize** based on data, then **background** slow non-critical work.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|---|---|---|---|
| Rewrite in Rust/C | Maximum performance | Massive effort, breaks codebase | Disproportionate to problem |
| Add async parallelism to all phases | Reduces wall-clock time | Complicates error handling, some phases depend on prior | Partial — apply only where safe |
| Full caching layer (Redis/memcached) | Distributes across instances | Operational complexity, VVP runs single-instance | Over-engineered for current scale |

### Detailed Design

#### Part 1: Timing Instrumentation

**File:** `services/verifier/app/vvp/timing.py` (new)

A lightweight phase timer that collects timing data for each verification request:

```python
@dataclass
class PhaseTimer:
    """Collects per-phase timing for a verification request."""
    timings: Dict[str, float]  # phase_name -> elapsed_ms
    _current_phase: Optional[str]
    _phase_start: Optional[float]

    def start(self, phase: str) -> None: ...
    def stop(self) -> float: ...
    def to_dict(self) -> Dict[str, float]: ...
```

**Integration:** Wrap each phase in `verify_vvp()` with `timer.start("phase_4_signature")` / `timer.stop()`. Log timing summary at INFO level. Expose in API response via optional `timing` field (controlled by config flag).

#### Part 2: Endpoint Health Tracker

**File:** `services/verifier/app/vvp/endpoint_health.py` (new)

Track success/failure/latency for external endpoints:

```python
@dataclass
class EndpointStats:
    url_pattern: str           # e.g. "schema.gleif.org/*"
    total_requests: int
    successes: int
    failures: int
    timeouts: int
    avg_latency_ms: float
    p95_latency_ms: float
    last_success: Optional[float]
    last_failure: Optional[float]
    consecutive_failures: int

class EndpointHealthTracker:
    """Tracks health of external endpoints with circuit breaker."""

    def record_success(self, url: str, latency_ms: float): ...
    def record_failure(self, url: str, error: str): ...
    def record_timeout(self, url: str): ...
    def is_healthy(self, url: str) -> bool: ...  # circuit breaker
    def get_stats(self) -> Dict[str, EndpointStats]: ...
```

**Circuit breaker:** After N consecutive failures (default 5), mark endpoint as unhealthy for M seconds (default 60). Skip unhealthy endpoints to avoid wasting timeout budget. Auto-recover by probing periodically.

**Integration:** Wrap all `httpx` calls in endpoint health recording. Expose via `/healthz/endpoints` API.

#### Part 3: Code-Level Optimizations

**3a. Module-level imports for hot-path dependencies**

Move these imports from function-level to module-level:

| File | Import | Call Frequency |
|------|--------|---------------|
| `keri/kel_parser.py:718` | `import pysodium` | Per signature |
| `keri/kel_parser.py:753,867` | `import blake3` | Per KEL event |
| `keri/cesr.py:298,324,415,875` | `import base64` | Per CESR segment |
| `keri/kel_parser.py:956` | `import math` | Per witness validation |
| `keri/signature.py:46,227` | `import pysodium` | Per verification |
| `canonical/keri_canonical.py:133` | `import re` | Per SAID computation |
| `verify.py:235` | `from urllib.parse import urlparse` | Duplicate — already at line 21 |
| `verify.py:851` | `import time as _time` | Per request |
| `verify.py:1203,1484` | `from datetime import datetime, timezone` | Per request |

**3b. OrderedDict for LRU caches**

Replace `list`-based `_access_order` with `OrderedDict` in:
- `verification_cache.py` (`VerificationResultCache`)
- `keri/cache.py` (`KeyStateCache`)

This changes `_touch()` from O(n) `list.remove()` + `list.append()` to O(1) `OrderedDict.move_to_end()`.

**3c. Cache `compute_config_fingerprint()`**

In `verification_cache.py`, compute the config fingerprint once at module load and store in a module-level variable. Config values come from `os.getenv()` at import time and never change.

**3d. B64 lookup table**

In `cesr.py`, replace `B64_CHARS.index(char)` (O(64) linear scan per char) with a pre-built `dict` lookup (O(1)).

**3e. Pre-compile regex patterns**

Move regex compilation to module level:
- `cesr.py:190` — CESR version string pattern
- `canonical/keri_canonical.py:167` — compact form version pattern

**3f. Shared `httpx.AsyncClient` for schema and TEL operations**

Create a module-level `httpx.AsyncClient` that is reused across calls (connection pooling, keepalive). Initialize on first use, close on shutdown.

- `acdc/schema_fetcher.py:67` — schema fetches
- `acdc/schema_resolver.py:411,501` — schema resolution
- `keri/tel_client.py:291,344` — TEL queries

This is the single highest-impact I/O optimization — connection reuse eliminates TCP+TLS handshake latency for repeated calls to the same host.

#### Part 4: Background Non-Critical Checks

**4a. Speculative revocation checking**

When verification cache hits, revocation data is already available. When it's stale, the current code enqueues a background re-check but still returns INDETERMINATE. This is correct. No change needed — just ensure the background checker actually runs (verify `RevocationChecker` is functional).

**4b. Schema prefetch on startup**

For the known vLEI schema SAIDs (embedded in `schema_store.py`), the embedded store already short-circuits network fetches. No change needed.

**4c. Witness TEL queries in parallel**

Change `tel_client.py` `check_revocation()` from sequential witness iteration to parallel `asyncio.gather()` with first-success-wins. This is the single most impactful latency optimization for Phase 9.

```python
# Current (sequential):
for witness_url in witness_urls:
    result = await self._query_witness(...)
    if result.status != CredentialStatus.ERROR:
        return result

# Proposed (parallel first-success):
tasks = [self._query_witness(cred, reg, url) for url in witness_urls]
for coro in asyncio.as_completed(tasks):
    result = await coro
    if result.status != CredentialStatus.ERROR:
        # Cancel remaining tasks
        for t in tasks: t.cancel()
        return result
```

### Data Flow

```
verify_vvp() request arrives
  │
  ├─ Phase 2-3: CPU parse (microseconds) ─ timer records
  │
  ├─ Cache check ─ O(1) with OrderedDict ─ timer records
  │   └─ (hit) → skip phases 4-9, use cached artifacts
  │
  ├─ Phase 4: OOBI fetch ─ health tracker records success/fail
  │   └─ uses shared httpx client (connection reuse)
  │
  ├─ Phase 5: Dossier fetch ─ health tracker records
  │   └─ uses shared httpx client
  │
  ├─ Phase 5.5: Chain validation
  │   ├─ Schema resolve ─ embedded store first (no network)
  │   │   └─ fallback: shared httpx client → health tracker
  │   └─ External SAID resolution ─ shared httpx client
  │
  ├─ Phase 9: Revocation ─ parallel witness queries
  │   └─ skip unhealthy witnesses (circuit breaker)
  │
  ├─ Phases 10-40: CPU-only (microseconds)
  │
  └─ Response includes optional timing breakdown
```

### Error Handling

- Endpoint health tracker failures are non-fatal (degrade gracefully to no circuit breaking).
- Timing instrumentation failures are non-fatal (log warning, continue without timing).
- Shared httpx client is created lazily; if creation fails, falls back to per-call clients.

### Test Strategy

1. **Unit tests for `PhaseTimer`** — verify timing collection, start/stop semantics.
2. **Unit tests for `EndpointHealthTracker`** — verify circuit breaker logic, stats accumulation.
3. **Unit tests for LRU optimization** — verify OrderedDict-based cache maintains correct eviction order.
4. **Integration test for parallel TEL queries** — mock witnesses, verify first-success-wins behavior.
5. **Regression tests** — all existing tests must pass unchanged (optimizations are behavioral no-ops).

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/verifier/app/vvp/timing.py` | Create | Phase timer instrumentation |
| `services/verifier/app/vvp/endpoint_health.py` | Create | Endpoint health tracking + circuit breaker |
| `services/verifier/app/vvp/verify.py` | Modify | Add timing instrumentation to all phases |
| `services/verifier/app/vvp/verification_cache.py` | Modify | OrderedDict LRU, cached config fingerprint |
| `services/verifier/app/vvp/keri/cache.py` | Modify | OrderedDict LRU |
| `services/verifier/app/vvp/keri/kel_parser.py` | Modify | Module-level imports (pysodium, blake3, math) |
| `services/verifier/app/vvp/keri/cesr.py` | Modify | Module-level imports, B64 lookup table, pre-compiled regex |
| `services/verifier/app/vvp/keri/signature.py` | Modify | Module-level pysodium import |
| `services/verifier/app/vvp/keri/tel_client.py` | Modify | Parallel witness queries, shared httpx client, health tracking |
| `services/verifier/app/vvp/acdc/schema_fetcher.py` | Modify | Shared httpx client |
| `services/verifier/app/vvp/acdc/schema_resolver.py` | Modify | Shared httpx client, health tracking |
| `services/verifier/app/vvp/keri/oobi.py` | Modify | Shared httpx client, health tracking |
| `common/common/vvp/canonical/keri_canonical.py` | Modify | Module-level re import, pre-compiled regex |
| `common/common/vvp/dossier/fetch.py` | Modify | Shared httpx client, health tracking |
| `services/verifier/app/main.py` | Modify | Register httpx client lifecycle, health endpoint |
| `services/verifier/tests/test_timing.py` | Create | PhaseTimer unit tests |
| `services/verifier/tests/test_endpoint_health.py` | Create | EndpointHealthTracker unit tests |
| `services/verifier/tests/test_parallel_tel.py` | Create | Parallel TEL query tests |

## Open Questions

1. **Should timing data be in the API response by default?** Recommendation: off by default, enabled via `VVP_TIMING_ENABLED=true` env var for profiling.
2. **Circuit breaker thresholds** — 5 consecutive failures / 60s cooldown are reasonable defaults. Should these be configurable?
3. **Shared httpx client lifetime** — Should it live for the app lifetime (with connection pool limits) or be recreated periodically?

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Shared httpx client leaks connections | Low | Medium | Configure pool limits, add shutdown hook |
| Parallel TEL queries overload witnesses | Low | Low | Limit to 3 concurrent per credential |
| Circuit breaker incorrectly marks healthy endpoint | Low | Medium | Conservative thresholds, auto-recovery probe |
| Module-level imports fail on missing deps | Low | High | Keep try/except for optional deps (blake3) |
| Timing instrumentation adds overhead | Very Low | Very Low | Timestamps are nanosecond-resolution, negligible |

## Exit Criteria

1. All existing tests pass unchanged
2. `PhaseTimer` captures timing for all phases in `verify_vvp()`
3. `EndpointHealthTracker` records stats for all external HTTP calls
4. `/healthz/endpoints` API returns endpoint health data
5. LRU caches use O(1) operations (OrderedDict)
6. Lazy imports moved to module level for hot-path code
7. TEL witness queries run in parallel
8. Shared httpx client reused across calls
9. Timing logs visible at INFO level for production profiling
