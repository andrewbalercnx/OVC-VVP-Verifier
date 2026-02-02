# Sprint 27: Local Witness Infrastructure

## Problem Statement

The VVP Issuer service requires local KERI witnesses for development and testing. Currently, the verifier relies on remote Provenant staging witnesses, but for local development of the issuer, we need witnesses running locally that can:
1. Accept OOBI requests for AID resolution
2. Store and serve KEL events
3. Provide witness receipts for credential issuance

Without local witnesses, developers cannot test issuer functionality without network connectivity to external witness infrastructure.

## Spec References

- SPRINTS.md §Sprint 27: Defines deliverables and exit criteria
- keripy witness demo: Uses `kli witness demo` to run deterministic demo witnesses

## Current State

- **No docker-compose.yml exists** - The project uses Azure Container Apps for deployment
- **Verifier has mature OOBI resolution** via `services/verifier/app/vvp/keri/witness_pool.py`
- **Configured with Provenant staging witnesses** as default fallback
- **keripy vendored** at `/keripy` with witness demo support

## Proposed Solution

### Approach

Use the `gleif/keri:latest` Docker image with `kli witness demo` to run three demo witnesses (wan, wil, wes) in a single container. Add environment variable support to the verifier config so it can use local witnesses instead of Provenant staging.

**Why this approach:**
1. `gleif/keri:latest` is the official GLEIF KERI image, well-maintained and tested
2. `kli witness demo` runs all witnesses in one process with deterministic AIDs
3. Single container simplifies orchestration (vs. 3 separate containers)
4. Environment variable override is non-invasive and backwards-compatible

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Build from vendored keripy | Full control, exact version match | Slower builds, more maintenance, dependency issues | Vendored keripy is for reference, not production |
| Separate container per witness | Better isolation, independent scaling | Requires keystore pre-initialization, more complex | Overkill for local dev |
| Modify default config | Simpler code | Breaks production, not backwards-compatible | Environment variable is cleaner |

### Detailed Design

#### Component 1: docker-compose.yml

**Purpose:** Multi-service orchestration for local development
**Location:** `/docker-compose.yml` (repository root)

```yaml
version: "3.8"

services:
  witnesses:
    image: gleif/keri:latest
    container_name: vvp-witnesses
    command: ["kli", "witness", "demo"]
    ports:
      - "5632:5632"  # wan TCP
      - "5633:5633"  # wil TCP
      - "5634:5634"  # wes TCP
      - "5642:5642"  # wan HTTP
      - "5643:5643"  # wil HTTP
      - "5644:5644"  # wes HTTP
    volumes:
      - witness-data:/usr/local/var/keri
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5642/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
    networks:
      - vvp-network

  verifier:
    build:
      context: .
      dockerfile: services/verifier/Dockerfile
    container_name: vvp-verifier
    ports:
      - "8000:8000"
    environment:
      - VVP_LOCAL_WITNESS_URLS=http://witnesses:5642,http://witnesses:5643,http://witnesses:5644
      - VVP_GLEIF_WITNESS_DISCOVERY=false
    depends_on:
      witnesses:
        condition: service_healthy
    networks:
      - vvp-network
    profiles:
      - full  # Only with: docker-compose --profile full up

networks:
  vvp-network:
    name: vvp-internal

volumes:
  witness-data:
```

#### Component 2: scripts/local-witnesses.sh

**Purpose:** Convenience script for starting/stopping witnesses
**Location:** `/scripts/local-witnesses.sh`

**Commands:**
- `start` - `docker-compose up -d witnesses` + health check
- `stop` - `docker-compose down`
- `status` - Check health of all three witnesses, print OOBI URLs
- `logs` - View witness logs

**Key features:**
- Color-coded output for status
- Health check verifies all three HTTP ports respond
- Prints OOBI URLs and environment variable for copy/paste

#### Component 3: services/issuer/config/witnesses.json

**Purpose:** Witness configuration for future issuer service (Sprint 28)
**Location:** `/services/issuer/config/witnesses.json`

```json
{
  "dt": "2026-01-31T00:00:00.000000+00:00",
  "iurls": [
    "http://witnesses:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller",
    "http://witnesses:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller",
    "http://witnesses:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller"
  ],
  "witness_aids": {
    "wan": "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
    "wil": "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
    "wes": "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"
  },
  "ports": {
    "wan": {"tcp": 5632, "http": 5642},
    "wil": {"tcp": 5633, "http": 5643},
    "wes": {"tcp": 5634, "http": 5644}
  }
}
```

#### Component 4: Config Update (config.py)

**Purpose:** Add environment variable support for local witness override
**Location:** `/services/verifier/app/core/config.py` (modify lines 390-396)

**Change:**
```python
# Before (hardcoded):
PROVENANT_WITNESS_URLS: list[str] = [
    "http://witness4.stage.provenant.net:5631",
    ...
]

# After (environment variable with fallback):
def _parse_witness_urls() -> list[str]:
    """Parse witness URLs from environment or use defaults."""
    local_urls = os.getenv("VVP_LOCAL_WITNESS_URLS", "")
    if local_urls:
        return [url.strip() for url in local_urls.split(",") if url.strip()]
    return [
        "http://witness4.stage.provenant.net:5631",
        "http://witness5.stage.provenant.net:5631",
        "http://witness6.stage.provenant.net:5631",
    ]

PROVENANT_WITNESS_URLS: list[str] = _parse_witness_urls()
```

#### Component 5: Integration Tests

**Purpose:** Verify witness functionality
**Location:** `/services/verifier/tests/test_local_witnesses.py`

**Tests (require `--run-local-witnesses` flag):**
1. `test_witness_wan_responds` - Verify port 5642 responds
2. `test_witness_wil_responds` - Verify port 5643 responds
3. `test_witness_wes_responds` - Verify port 5644 responds
4. `test_oobi_endpoint_returns_keri_data` - Verify OOBI returns KERI messages
5. `test_witness_pool_with_local_urls` - Verify WitnessPool integration

### Data Flow

```
Developer Machine                    Docker Network
┌─────────────────┐                 ┌─────────────────────────────┐
│                 │   docker-compose│                             │
│  ./scripts/     │ ───────────────>│  witnesses container        │
│  local-witnesses│    up           │  ├── wan :5642              │
│  .sh start      │                 │  ├── wil :5643              │
│                 │                 │  └── wes :5644              │
└─────────────────┘                 │                             │
                                    │  verifier container         │
┌─────────────────┐                 │  └── uses local witnesses   │
│  Verifier       │   env var       │      via VVP_LOCAL_WITNESS_ │
│  (local dev)    │ ───────────────>│      URLS env var           │
│                 │                 └─────────────────────────────┘
└─────────────────┘
        │
        │ export VVP_LOCAL_WITNESS_URLS=...
        ▼
    Uses local witnesses instead of Provenant
```

### Error Handling

- Docker not installed: Script exits with clear error message
- Witnesses fail to start: Health check reports which witness failed
- Port conflicts: User must stop conflicting services (ports 5632-5634, 5642-5644)

### Test Strategy

1. **Unit tests:** None needed (configuration change only)
2. **Integration tests:** New `test_local_witnesses.py` with pytest marker
3. **Manual verification:** Script includes `status` command for health check

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `docker-compose.yml` | Create | Multi-service orchestration |
| `scripts/local-witnesses.sh` | Create | Start/stop convenience script |
| `services/issuer/config/witnesses.json` | Create | Issuer witness config (Sprint 28) |
| `services/issuer/config/.gitkeep` | Create | Ensure directory in git |
| `services/verifier/app/core/config.py` | Modify | Add env var support |
| `services/verifier/tests/test_local_witnesses.py` | Create | Integration tests |

## Open Questions

1. **Port conflicts:** Should we add a check for port availability before starting witnesses, or just document the requirement?

2. **Verifier in docker-compose:** The plan includes verifier as optional (`--profile full`). Should it be included by default, or is witnesses-only the primary use case?

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| `gleif/keri:latest` unavailable | Low | High | Fall back to building from vendored keripy |
| Port conflicts | Medium | Medium | Document requirements, add check in script |
| Docker not installed | Medium | Low | Document as prerequisite |
| Witness AIDs change | Low | Low | AIDs are deterministic from hardcoded salts |

## Known Witness AIDs

These are deterministic from `kli witness demo` salts:

| Name | AID | TCP Port | HTTP Port |
|------|-----|----------|-----------|
| wan | `BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha` | 5632 | 5642 |
| wil | `BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM` | 5633 | 5643 |
| wes | `BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX` | 5634 | 5644 |

## Exit Criteria

Per SPRINTS.md:
- [ ] `docker-compose up` starts all witnesses
- [ ] `curl http://127.0.0.1:5642/oobi/{wan_aid}/controller` returns valid OOBI
- [ ] Verifier tests pass with local witness resolution

---

## Implementation Notes

### Reviewer Feedback Incorporated

1. **Healthcheck alignment**: Changed healthcheck from `http://localhost:5642/` to OOBI endpoint for stronger readiness signal
2. **Port check added**: `local-witnesses.sh` includes port availability check before starting
3. **Port discrepancy fixed**: Updated SPRINTS.md to show correct ports from `kli witness demo`
4. **Verifier profile**: Kept optional via `--profile full` as recommended

### Deviations from Plan

None - implementation matches approved plan.

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `docker-compose.yml` | +87 | Docker orchestration for witnesses + optional verifier |
| `scripts/local-witnesses.sh` | +175 | Start/stop script with health checks |
| `services/issuer/config/witnesses.json` | +24 | Witness config for Sprint 28 issuer |
| `services/issuer/config/.gitkeep` | +1 | Placeholder for git |
| `services/verifier/app/core/config.py` | +22 | VVP_LOCAL_WITNESS_URLS env var support |
| `services/verifier/tests/test_local_witnesses.py` | +175 | Integration tests |
| `SPRINTS.md` | +4 | Fixed port documentation |

### Test Results

Docker is not available on the current machine. Manual verification required:

```bash
# Start witnesses
./scripts/local-witnesses.sh start

# Verify OOBI endpoint
curl http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller

# Run integration tests
export VVP_LOCAL_WITNESS_URLS=http://127.0.0.1:5642,http://127.0.0.1:5643,http://127.0.0.1:5644
./scripts/run-tests.sh tests/test_local_witnesses.py -v --run-local-witnesses
```
