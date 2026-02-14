# KERI — Key Event Receipt Infrastructure

## What KERI Is

KERI is a decentralized key management infrastructure (DKMI) that provides cryptographic root-of-trust for identifiers without X.509 certificates or blockchain. Authority is established via **verifiable key state** recorded in append-only event logs.

## Core Primitives

### AID (Autonomic Identifier)
- Self-certifying identifier derived from public key material
- Transferable AIDs support key rotation via pre-rotation
- Non-transferable AIDs are permanently bound to a single key
- In VVP: used for PASSporT signers, credential issuers, trusted roots

### KEL (Key Event Log)
- Append-only, backward+forward chained log of key events
- Event types: `icp` (inception), `rot` (rotation), `ixn` (interaction)
- Each event has a SAID (`d` field) and references prior event digest (`p`)
- Key state is derived by replaying the KEL from inception
- In VVP: resolved via OOBI to verify PASSporT signatures

### Pre-Rotation
- Each establishment event commits to **next** keys via digest (`n` field)
- Provides forward security and recovery from key compromise
- Rotation reveals previously committed keys and commits to new next keys

### Witnesses
- Designated nodes that verify, sign receipts, and store KELs
- Provide distributed consensus via KAACE (no blockchain needed)
- Witness threshold (TOAD) sets minimum receipts for accountability
- In VVP: 3-witness pool (wan, wil, wes) on ports 5642-5644

### OOBI (Out-of-Band Introduction)
- URL that associates an AID with a network endpoint
- Format: `http://host:port/oobi/{AID}`
- Trust model: "discovery via URI, trust via KERI" — OOBI is untrusted, all data cryptographically verified
- In VVP: `kid` field in PASSporT, `evd` field in VVP-Identity header

### TEL (Transaction Event Log)
- Tracks credential issuance (`iss`/`bis`) and revocation (`rev`/`brv`)
- Anchored to issuer's KEL via interaction event seals
- In VVP: revocation checking in verification Phase 9

## CESR (Composable Event Streaming Representation)
- Binary-to-text encoding for events and signatures
- All cryptographic material as qualified Base64 strings with derivation codes
- Self-framing: each primitive includes its type code
- Key code: `E` prefix = Blake3-256 SAID (44 chars)
- In VVP: dossier streams contain CESR-encoded ACDCs + signature attachments

## Key Events Structure
```json
{
  "v": "KERI10JSON...",   // version string
  "t": "icp",            // event type
  "d": "E...",           // SAID of this event
  "i": "E...",           // AID prefix
  "s": "0",              // sequence number (hex)
  "kt": "1",             // signing threshold
  "k": ["D..."],         // current public keys
  "nt": "1",             // next threshold
  "n": ["E..."],         // next key digests (pre-rotation)
  "bt": "2",             // witness threshold (TOAD)
  "b": ["B...", "B..."]  // witness AIDs
}
```
