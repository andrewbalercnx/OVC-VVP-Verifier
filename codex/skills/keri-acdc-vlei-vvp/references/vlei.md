# vLEI — Verifiable Legal Entity Identifier

## What vLEI Is

The vLEI ecosystem provides cryptographically verifiable organizational identity credentials. Governed by GLEIF (Global Legal Entity Identifier Foundation), it creates a hierarchical trust chain from root authority through intermediaries to end entities.

## Trust Hierarchy

```
GLEIF Root AID (ultimate trust anchor)
  └── QVI Credential (Qualified vLEI Issuer)
        └── LE Credential (Legal Entity)
              ├── OOR Credential (Official Organizational Role)
              └── ECR Credential (Engagement Context Role)
```

## Credential Types

| Type | Abbreviation | Issuer | Issuee | Purpose |
|------|-------------|--------|--------|---------|
| QVI | Qualified vLEI Issuer | GLEIF | QVI org | Authorizes org to issue LE credentials |
| LE | Legal Entity | QVI | Legal entity | Binds LEI to KERI AID |
| OOR | Official Org Role | QVI (w/ auth) | Individual | Attests official role (CEO, CFO, etc.) |
| ECR | Engagement Context Role | QVI (w/ auth) | Individual | Attests functional role |
| OOR Auth | OOR Authorization | Legal entity | QVI | Authorizes QVI to issue OOR |
| ECR Auth | ECR Authorization | Legal entity | QVI | Authorizes QVI to issue ECR |

## Schema SAIDs Used in VVP

| Schema | SAID | Used For |
|--------|------|----------|
| Legal Entity (LE) | `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY` | Identity vetting credential |
| Cooperative Delegation (GCD) | `EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o` | delsig, alloc edges |
| TN Allocation (RTU) | `EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ` | tnalloc edge |
| VVP Dossier | `EH1jN4U4LMYHmPVI4FYdZ10bIPR7YWKp8TDdZ9Y9Al-P` | Dossier ACDC |

## vLEI Governance Rules

1. **GLEIF Root**: Only GLEIF issues QVI credentials
2. **QVI Delegation**: QVIs issue LE credentials after LEI verification
3. **Role Authorization**: QVIs need authorization credentials from LE before issuing OOR/ECR
4. **Identity Assurance**: IAL2 (NIST 800-63A) minimum for individual credentials
5. **Revocation Cascade**: Revoking parent may invalidate child credentials
6. **90-Day Grace Period**: Credentials have grace period for renewal/transfer

## VVP-Specific Extensions

VVP extends the vLEI model with additional credential types:

| Credential | Purpose | Key Edge |
|------------|---------|----------|
| **APE** (Auth Phone Entity) | Authorizes entity for phone operations | `vetting` → LE |
| **DE** (Delegate Entity) | Delegates signing authority | `delegation` → APE/DE |
| **TNAlloc** (TN Allocation) | Allocates telephone numbers | `jl` → parent allocator |
| **Brand** (Brand Owner) | Associates brand identity | Links to LE |
| **Dossier** (CVD) | Bundles all credentials for a call identity | Root of the DAG |

### TNAlloc "numbers" Attribute
VVP TNAlloc credentials use `"numbers"` attribute (not `"tn"` or `"phone"`). Detection must check all three attribute names for compatibility.
