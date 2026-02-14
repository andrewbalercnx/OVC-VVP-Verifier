# KERI/ACDC/vLEI/VVP Domain Skill

This skill provides domain context for reviewing code in the VVP (Verified Voice Protocol) monorepo. VVP extends STIR/SHAKEN by replacing X.509 certificate chains with KERI-based decentralized identifiers and ACDC verifiable credentials.

## When to Use

Prepend this context pack before any code or plan review that touches:
- ACDC credential issuance, validation, or chain walking
- KERI identity management (AID, KEL, witnesses, OOBI)
- Dossier creation, building, or verification
- PASSporT JWT signing or verification
- Schema SAIDs, edge operators (I2I, NI2I), credential types
- TN allocation, delegation (delsig), brand credentials
- vLEI governance concepts (QVI, LE, GLEIF root of trust)

## Reference Documents

| File | Content | When Needed |
|------|---------|-------------|
| `references/keri.md` | KERI protocol: AID, KEL, witnesses, OOBI, CESR | Always for protocol reviews |
| `references/acdc.md` | ACDC credentials: structure, edges, operators, SAID | Credential issuance/verification |
| `references/vlei.md` | vLEI governance: GLEIF → QVI → LE chain, schemas | Trust chain, schema reviews |
| `references/vvp.md` | VVP spec: PASSporT, dossier, delegation, TN rights | VVP-specific features |
| `references/glossary.md` | Key terms and acronyms | Always |
| `references/source-map.md` | Codebase file locations and purposes | Code reviews |

## Context Profiles

| Profile | Includes | Use Case |
|---------|----------|----------|
| `default` | glossary + source-map | Lightweight context |
| `review-plan` | ALL references | Plan reviews need full domain context |
| `review-code` | vvp + acdc + glossary + source-map | Code reviews need implementation context |
