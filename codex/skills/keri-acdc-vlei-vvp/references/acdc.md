# ACDC — Authentic Chained Data Containers

## What ACDCs Are

ACDCs are self-describing, cryptographically bound verifiable credentials that form directed acyclic graphs (DAGs) through edge references. Each ACDC provides proof-of-authorship and can chain to other ACDCs to build complex authorization hierarchies.

## ACDC Structure

```json
{
  "v": "ACDC10JSON...",     // version string
  "d": "SAID",              // self-addressing identifier (content hash)
  "i": "AID of issuer",     // who issued this credential
  "ri": "Registry SAID",    // TEL tracking credential status
  "s": "Schema SAID",       // what type of credential (immutable schema)
  "a": {                    // attributes block
    "d": "SAID",
    "i": "AID of issuee",   // who this credential is about (optional for CVD)
    "dt": "ISO8601",        // issuance datetime
    ...                     // type-specific attributes
  },
  "e": {                    // edges block (links to other ACDCs)
    "d": "SAID",
    "edgename": {
      "n": "SAID of target ACDC",
      "s": "Schema SAID constraint",
      "o": "I2I"            // edge operator
    }
  },
  "r": { ... }              // rules block (Ricardian contracts)
}
```

### Required Fields: `v`, `d`, `i`, `s`

### CVD (Compact Verifiable Document)
- No issuee (`a.i` absent or null)
- Asserted to the world, not issued to a specific party
- VVP dossiers are CVDs — no issuee field

## SAID (Self-Addressing Identifier)

1. Replace `d` field with placeholder `#` characters (exact target length)
2. Serialize to canonical form (insertion-ordered JSON, no whitespace)
3. Compute Blake3-256 hash
4. Encode as CESR Base64 (44 chars, `E` prefix)
5. Replace placeholder with computed SAID

**Critical**: SAIDs computed recursively — inner sections first, then outer.

## Edge Operators

| Operator | Constraint | Use Case |
|----------|-----------|----------|
| **I2I** (Issuer-to-Issuee) | Child issuer MUST be parent issuee | Default. Authority delegation chains |
| **NI2I** (Not-I2I) | No relationship required | Referential links, supporting evidence |
| **DI2I** (Delegated-I2I) | Child issuer must be parent issuee OR delegated from them | Extended delegation |

### I2I Validation
```
child_credential.i  ==  parent_credential.a.i
(child issuer AID)      (parent issuee AID)
```

### VVP Edge Operators
| Edge | Operator | Reason |
|------|----------|--------|
| `vetting` | NI2I | LE credential not necessarily issued to AP |
| `alloc` | I2I | Service allocation granted TO the AP org |
| `tnalloc` | I2I | TN allocation granted TO the AP org |
| `delsig` | NI2I | Delegation issued BY the AP, not TO them |
| `bownr` | NI2I | Brand ownership reference |
| `bproxy` | *(none)* | Cross-entity brand proxy |

## Credential Lifecycle

### Issuance
1. Issuer creates ACDC, computes SAIDs recursively
2. Issuer signs (anchored to KEL via interaction event)
3. Registered in TEL (`iss` event)
4. Published to witnesses

### Revocation
1. Issuer creates TEL revocation event (`rev`)
2. Anchored to issuer's KEL
3. Verifiers check TEL status during validation

### Verification
1. Validate SAID integrity (recompute and compare)
2. Verify issuer signature against KEL key state
3. Check schema compliance
4. Check TEL for revocation status
5. Walk edge chains, validate operator constraints
6. Trace to trusted root AID

## ACDC Variants
- **Full**: All attributes expanded inline
- **Compact**: Attributes replaced by SAID references
- **Partial**: Some attributes expanded, others compacted
- If compact ACDC references SAID not in dossier → status is **INDETERMINATE** (not INVALID)
