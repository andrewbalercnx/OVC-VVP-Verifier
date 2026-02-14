# VVP — Verified Voice Protocol

## What VVP Is

VVP extends STIR/SHAKEN by replacing X.509 certificate chains with KERI-based decentralized identifiers and ACDC credentials. It provides cryptographic proof-of-rights for VoIP calls, including brand identity, telephone number authorization, and delegation evidence.

## VVP Headers

### VVP-Identity Header
Base64url-encoded JSON containing:
```json
{
  "kid": "OOBI URL for signer's KEL",
  "evd": "URL to fetch the dossier (evidence)"
}
```
- `kid`: resolves to witness endpoint → KEL → public key for signature verification
- `evd`: resolves to dossier endpoint → CESR/JSON stream of ACDCs

### PASSporT JWT
RFC 8225 Personal Assertion Token, signed with Ed25519:
- **Header**: `{"alg": "EdDSA", "ppt": "shaken", "typ": "passport", "x5u": "..."}`
- **Payload**: `{"attest": "A/B/C", "dest": {"tn": [...]}, "iat": <unix>, "orig": {"tn": "..."}, "origid": "..."}`
- VVP mandates EdDSA (Ed25519) only — no RSA, no ECDSA
- Max `iat` drift: 5 seconds (§5.2A)
- Max token age: 300 seconds (configurable, §5.2B)

## Dossier Structure

A dossier is a DAG of ACDCs that proves a caller's rights. The dossier schema is `EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P` (CVD — no issuee).

### Dossier Edge Structure
```
Dossier ACDC (root)
  ├── edge "vetting"  → LE Credential (identity vetting, NI2I)
  ├── edge "alloc"    → GCD Credential (service allocation, I2I)
  ├── edge "tnalloc"  → TNAlloc Credential (TN rights, I2I)
  ├── edge "delsig"   → GCD Credential (delegation evidence, NI2I)
  ├── edge "bownr"    → Brand Credential (brand ownership, NI2I, optional)
  └── edge "bproxy"   → Brand Proxy (cross-entity, optional)
```

### Required Edges: `vetting`, `alloc`, `tnalloc`, `delsig`
### Optional Edges: `bownr`, `bproxy`

### bproxy Rule (§6.3.4)
When `bownr` is present and delsig issuee (OP) ≠ AP: `bproxy` is **REQUIRED** (hard error).
When OP == AP (self-signing): `bproxy` is optional even with `bownr`.

## Verification Pipeline (11 Phases)

| Phase | Name | What It Does |
|-------|------|-------------|
| 1 | Input Validation | Validate request structure |
| 2 | VVP-Identity Parse | Decode base64url JSON header |
| 3 | PASSporT Parse | Parse JWT, bind to VVP-Identity |
| 4 | Signature Verify | Resolve KEL via OOBI, verify Ed25519 signature |
| 5 | Dossier Fetch | HTTP GET from `evd` URL, parse CESR/JSON stream |
| 6 | DAG Validation | Build credential DAG, check structure (cycles, single root) |
| 7-8 | ACDC Verification | Verify ACDC signatures, check SAIDs |
| 9 | Revocation Check | Query TEL for each credential's status |
| 10 | Chain Validation | Walk credential chain to trusted root AID |
| 11 | Authorization | Check TN rights (TNAlloc), delegation (delsig), brand |

### Verification Result: `VALID` | `INVALID` | `INDETERMINATE`

## Delegation Model

### Parties
- **AP** (Accountable Party): Signs the dossier. Dossier's `i` field = AP's AID.
- **OP** (Originating Party): Signs PASSporTs. Authorized via `delsig` edge.

### delsig Credential
- Issuer = AP's AID (issuer field `i`)
- Issuee = OP's AID (attribute field `a.i` / `recipient_aid`)
- Schema: GCD (`EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o`)
- Verifier checks: PASSporT signer AID == delsig issuee AID (§5.1 step 9)

## TN Authorization

### TN Allocation Credentials
- Schema: `EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ`
- Attributes include `"numbers"` field (array of TN ranges)
- I2I edge: AP org is the issuee (credential granted TO them)
- Must be linked as edges of the brand credential to appear in dossier (DFS walk)

### TN Lookup Flow (Issuer)
```
Incoming call with caller TN
  → Look up TN mapping (DB)
  → Find dossier for mapped org
  → Verify TNAlloc credentials cover the TN
  → Build PASSporT + VVP-Identity headers
  → Return 302 redirect with headers
```

## Brand Credentials

- Brand info (name, logo URL) is extracted from dossier during verification
- Brand derived from dossier only — signing 302 has no X-VVP-* headers
- Logo served via issuer `/static/` mount (`web/` directory → `/static/` URL)

## Key Configuration

| Setting | Value | Source |
|---------|-------|--------|
| Signature Algorithm | EdDSA (Ed25519) | §5.0, §5.1 (mandatory) |
| Max iat Drift | 5 seconds | §5.2A |
| Max PASSporT Validity | 300 seconds | §5.2B (configurable) |
| Clock Skew | ±300 seconds | §4.1A (configurable) |
| SAID Algorithm | Blake3-256 | KERI ecosystem standard |
