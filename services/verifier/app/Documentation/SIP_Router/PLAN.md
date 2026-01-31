# VVP SIP Router Extension Plan

**Status:** Exploratory Design (documentation for future implementation)

## Summary

Extend the VVP Verifier to act as a SIP router that receives SIP INVITEs with VVP headers, validates them via the existing `/verify` endpoint, and returns SIP 302 redirects based on configurable business logic policies.

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Infrastructure | Azure VM | Simpler ops than AKS, full UDP control |
| Fail policy | Configurable | Policy.yaml determines per-deployment |
| SIP transport | UDP only | Standard SIP, simplest implementation |
| Timeline | Exploratory | Document architecture for future |

## Architecture Decision: Separate Microservice (Option B)

**Rationale:**
- Azure Container Apps does NOT support UDP (required for SIP on port 5060)
- Clean separation: SIP handling isolated from HTTP verification
- Existing VVP Verifier remains unchanged
- Azure VM provides simpler ops than AKS with full UDP control

```
                     +------------------+
                     |   Azure VM       |
+------------+       |   (UK South)     |       +------------------+
| SIP Client | INVITE|  +------------+  | HTTPS | VVP Verifier     |
| (Caller)   |------>|  | SIP Router |-------->| (existing)       |
+------------+ UDP   |  | Python     |  |       | Container App    |
      ^        5060  |  +------------+  |       +------------------+
      | 302          |        |         |
      +--------------+  policy.yaml     |
                     +------------------+
```

## Module Structure

```
app/sip/                    # NEW: SIP Router package
├── __init__.py
├── server.py               # UDP listener (asyncio)
├── parser.py               # SIP message parsing
├── models.py               # SIPRequest, SIPResponse, RoutingDecision
├── policy.py               # Routing policy engine
├── router.py               # Main orchestrator
├── verifier_client.py      # HTTP client to VVP Verifier
└── responses.py            # SIP response builders

infra/
├── vm-setup.sh             # VM provisioning script
└── policy.yaml             # Default routing policy
```

## Business Logic Policy System

Policy configuration (YAML) defines actions for each verification outcome:

```yaml
policies:
  on_valid:
    action: redirect
    destination_template: "sip:{dest}@verified.carrier.example.com"
    headers:
      X-VVP-Status: "VALID"
      P-Asserted-Identity: "<sip:{orig}@verified.carrier.example.com>"

  on_invalid:
    action: reject
    reason_code: 403
    reason_phrase: "Forbidden - VVP Verification Failed"
    headers:
      X-VVP-Status: "INVALID"
      X-VVP-Error: "{errors[0].code}"

  on_indeterminate:
    # CONFIGURABLE: Choose fail-open or fail-closed per deployment
    action: redirect           # fail-open: route to unverified
    # action: reject           # fail-closed: block the call
    destination_template: "sip:{dest}@unverified.carrier.example.com"
    reason_code: 503           # Used if action=reject
    reason_phrase: "Service Unavailable - Verification Pending"
    headers:
      X-VVP-Status: "INDETERMINATE"

  on_error:
    # Verifier communication failure
    action: redirect           # Default: fail-open
    destination_template: "sip:{dest}@fallback.carrier.example.com"
    headers:
      X-VVP-Status: "ERROR"
```

**Template variables:** `{orig}`, `{dest}`, `{call_id}`, `{request_id}`, `{claims}`, `{errors}`

## VVP Header Transport in SIP

Two options for carrying VVP credentials in SIP:

1. **Custom headers** (recommended for clarity):
   - `P-VVP-Identity`: Base64url VVP-Identity JSON
   - `P-VVP-Passport`: PASSporT JWT

2. **Standard Identity header** (RFC 8224):
   - `Identity`: Contains the PASSporT JWT directly

## Azure Infrastructure Requirements

| Current | Required |
|---------|----------|
| Container Apps (HTTP only) | Azure VM with public IP |
| Port 8000/TCP | Port 5060/UDP for SIP |
| No IaC | VM setup script or Bicep template |

**Network path:**
- Internet -> Azure VM (public IP, UDP 5060) -> SIP Router process
- SIP Router -> HTTPS (Azure backbone) -> Container Apps -> VVP Verifier

**VM Configuration:**
- Size: Standard_B2s (2 vCPU, 4 GB) sufficient for moderate load
- OS: Ubuntu 22.04 LTS
- NSG rules: Allow UDP 5060 inbound, HTTPS outbound
- Static public IP for DNS registration

## SIP Library Approach

**Recommendation:** Custom minimal SIP parser

- Only needs: INVITE parsing, header extraction, 302/4xx response generation
- Avoids unmaintained library dependencies (aiosip deprecated)
- Focused on VVP use case, not full SIP stack

**Alternative:** Evaluate [PySIPio](https://pypi.org/project/PySIPio/) if fuller SIP support needed

## Implementation Phases (Future)

When ready to implement, the work breaks down into these phases:

### Phase 9A: Core SIP Parsing
- Implement SIP data models (`app/sip/models.py`)
- Build SIP message parser (`app/sip/parser.py`) - INVITE focus
- Create UDP server (`app/sip/server.py`)
- Unit tests for parser

### Phase 9B: VVP Integration
- Implement verifier HTTP client (`app/sip/verifier_client.py`)
- Extract VVP headers from SIP (P-VVP-Identity, Identity)
- Create routing orchestrator (`app/sip/router.py`)
- Integration tests with mock verifier

### Phase 9C: Policy Engine
- Implement policy engine (`app/sip/policy.py`)
- YAML configuration loading
- Template variable rendering
- Unit tests for all policy paths (VALID/INVALID/INDETERMINATE/ERROR)

### Phase 9D: SIP Responses
- Implement 302 redirect builder (`app/sip/responses.py`)
- Implement rejection response builder (403, 503)
- Header injection per policy

### Phase 9E: Deployment
- VM setup script (`infra/vm-setup.sh`)
- Systemd service configuration
- Structured logging with Call-ID correlation
- E2E tests with `sipp`

## Key Files (Future Implementation)

| File | Action | Purpose |
|------|--------|---------|
| `app/sip/models.py` | Create | SIPRequest, SIPResponse, RoutingDecision |
| `app/sip/parser.py` | Create | SIP message parser (RFC 3261) |
| `app/sip/server.py` | Create | UDP listener (asyncio) |
| `app/sip/policy.py` | Create | Routing policy engine |
| `app/sip/router.py` | Create | Main orchestrator |
| `app/sip/verifier_client.py` | Create | HTTP client to VVP Verifier |
| `app/sip/responses.py` | Create | SIP response builders |
| `app/core/config.py` | Modify | Add SIP configuration constants |
| `infra/vm-setup.sh` | Create | Azure VM provisioning |
| `infra/policy.yaml` | Create | Default routing policy |
| `tests/sip/*.py` | Create | SIP module tests |

## Configuration Constants (Future)

```python
# app/core/config.py additions
SIP_LISTEN_HOST = "0.0.0.0"
SIP_LISTEN_PORT = 5060
SIP_TRANSPORT = "UDP"
VVP_VERIFIER_URL = "https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io"
VVP_VERIFIER_TIMEOUT_SECONDS = 5.0
SIP_POLICY_CONFIG_PATH = "/etc/vvp/policy.yaml"
```

## Testing Strategy (Future)

1. **Unit tests:** Parser, policy engine, response builders
2. **Integration tests:** Mock verifier responses, verify routing decisions
3. **E2E tests:** Use `sipp` tool to send real SIP INVITEs

```bash
# Run SIP unit tests
python3 -m pytest tests/sip/ -v

# E2E with sipp (after deployment)
sipp -sf invite_vvp.xml -m 10 <vm-public-ip>:5060
```

## Risks and Considerations

| Risk | Mitigation |
|------|------------|
| SIP parsing complexity | Focus on INVITE only; custom minimal parser |
| VM single point of failure | Future: add second VM with DNS failover |
| Verifier latency impacts SIP timing | 5-second timeout; async handling |
| UDP packet loss | SIP retransmission at client handles this |

## References

- RFC 3261: SIP Protocol
- RFC 8224: Authenticated Identity (PASSporT in SIP)
- VVP Specification: `VVP_Verifier_Specification_v1.4_FINAL.md`
- Azure VM networking: UDP fully supported on public IPs
