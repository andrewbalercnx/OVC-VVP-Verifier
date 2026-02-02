# VVP Verifier Roadmap

**Last Updated:** 2026-01-25
**Current Status:** Tier 2 In Progress (54% overall)

This document provides a strategic view of VVP Verifier development. For detailed task tracking, see [Implementation Checklist](app/Documentation/VVP_Implementation_Checklist.md).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         VVP Verifier                            │
├─────────────────────────────────────────────────────────────────┤
│  Tier 1: Direct Verification                         [COMPLETE] │
│  ├── VVP-Identity parsing                                       │
│  ├── PASSporT JWT validation                                    │
│  ├── Ed25519 signature (key from AID)                          │
│  └── Dossier fetch + DAG validation                            │
├─────────────────────────────────────────────────────────────────┤
│  Tier 2: Full KERI Verification                   [IN PROGRESS] │
│  ├── OOBI resolution (kid → KEL)                    [DONE]      │
│  ├── CESR parsing                                   [DONE]      │
│  ├── Historical key state at T                      [DONE]      │
│  ├── Delegation validation                          [TODO]      │
│  ├── ACDC signature verification                    [TODO]      │
│  └── TEL revocation checking                        [TODO]      │
├─────────────────────────────────────────────────────────────────┤
│  Tier 3: Authorization                          [NOT STARTED]   │
│  ├── TNAlloc credential verification                            │
│  ├── Delegation chain validation                                │
│  ├── Brand credential verification                              │
│  └── Business logic constraints                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tier 2: KERI Verification (Current Focus)

### Completed ✓

| Component | Description | Files |
|-----------|-------------|-------|
| OOBI Dereferencing | Fetch KEL from witness OOBI URL | `oobi.py` |
| CESR Parsing | Parse `application/json+cesr` streams | `cesr.py`, `kel_parser.py` |
| KEL Validation | Chain continuity, signature verification | `kel_parser.py` |
| Key State at T | Historical key lookup per `iat` | `kel_resolver.py` |
| Caching | LRU cache with TTL for key state | `cache.py` |
| Canonical Serialization | KERI field ordering | `keri_canonical.py` |
| Live Witness | Tested with Provenant staging | `tel_client.py` |

### In Progress

| Component | Description | Blocking Issue |
|-----------|-------------|----------------|
| Delegation | `dip`/`drt` event validation | Raises `DelegationNotSupportedError` |
| Witness Sig Validation | Verify receipt signatures | Currently presence-only check |

### Not Started

| Component | Description | Spec Reference |
|-----------|-------------|----------------|
| ACDC Verification | Signature + SAID validation | §5.1.1-2.8 |
| TEL Resolution | Credential revocation status | §5.1.1-2.9 |
| SAID Validation | Blake3-256 most compact form | KERI spec |

---

## Tier 3: Authorization (Future)

| Component | Description | Spec Reference |
|-----------|-------------|----------------|
| TNAlloc | Phone number rights verification | §5.1.1-2.11 |
| Delegation Chain | Multi-hop authorization | §5.1.1-2.10, §7.2 |
| Brand Credentials | Rich call data verification | §5.1.1-2.12 |
| Business Logic | Goal matching, constraints | §5.1.1-2.13 |
| Callee Verification | Separate verification flow | §5.2 |

---

## Normative Requirements

### `kid` Field Semantics (Critical)

Per VVP draft and KERI specifications:

> **`kid` is an OOBI reference to a KERI autonomous identifier whose historical key state, witness receipts, and delegations MUST be resolved and validated to determine which signing key was authorised at the PASSporT reference time.**

This means:
- `kid` is NOT a generic key ID or X.509 URL
- Resolution requires OOBI dereferencing, not simple HTTP fetch
- Key state must be validated at reference time T (from `iat`)
- Witness receipts provide decentralized trust

### Reference Time T

All verification is relative to PASSporT `iat`, not wall clock:
- Key must be valid at T
- Credential must not be revoked at T
- Delegation must be active at T

---

## Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Delegation not supported | Cannot verify delegated AIDs | Raises clear error |
| SAID validation optional | Test mode only | Production requires Blake3 |
| Witness sigs not validated | Reduced trust assurance | Threshold check only |
| TEL not queried | Cannot detect revocation | Deferred to Phase 9 |

---

## Integration Points

### Provenant OVC Witnesses

```
http://witness4.stage.provenant.net:5631/oobi/{AID}/witness
http://witness5.stage.provenant.net:5631/oobi/{AID}/witness
http://witness6.stage.provenant.net:5631/oobi/{AID}/witness
```

### OOBI URL Format

```
http://<witness-host>:<port>/oobi/<AID>[/witness][/<witness-eid>]
```

### Response Format

- Content-Type: `application/json+cesr`
- Body: CESR stream with KEL events + attachments

---

## Next Steps (Priority Order)

1. **Complete Phase 7** - Delegation validation, witness signature verification
2. **Phase 8** - ACDC signature verification with SAID validation
3. **Phase 9** - TEL revocation checking
4. **Enable production** - Set `TIER2_KEL_RESOLUTION_ENABLED=True`

---

## Contributing

See [CLAUDE.md](CLAUDE.md) for the pair programming workflow used in this project.

---

## References

- [VVP Draft Specification](https://dhh1128.github.io/vvp/draft-hardman-verifiable-voice-protocol.html)
- [KERI Specification](https://keri.one)
- [Implementation Checklist](app/Documentation/VVP_Implementation_Checklist.md)
- [VVP Verifier Spec v1.5](app/Documentation/VVP_Verifier_Specification_v1.5.md)
