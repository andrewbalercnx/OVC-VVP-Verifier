# Creating Dossiers (ACDCs)

This note captures the capabilities, infrastructure, and components needed to
create ACDCs and assemble a dossier suitable for VVP verification. It is
intentionally implementation-agnostic, with pointers to KERI/keripy tooling and
operational requirements.

## Overview

A dossier is a DAG of ACDCs (credentials) that collectively support claims. To
create one, you need:

- An issuer identity with a KERI AID.
- Schemas that define each credential's semantics.
- A credential registry (TEL) to anchor issuance and revocations.
- Witness infrastructure to provide receipts and key-state resolution.
- A distribution endpoint (evd/OOBI URL) that serves the dossier.

## Required Capabilities

1. **KERI identifier management**
   - Create and rotate AIDs for issuers (and possibly subjects).
   - Maintain key state history (KEL) for each AID.
   - Publish OOBIs so verifiers can resolve key state.

2. **Witness support**
   - A witness node to store receipts and support key-state resolution.
   - For development, run a local witness using `keripy` and `kli witness`.
   - For production, use a reliable witness service (SLA-backed).

3. **Credential registry (TEL)**
   - Issue/revoke events are anchored to a registry for each credential.
   - Registries must be discoverable by verifiers via OOBI or known endpoints.

4. **Schema definition and publishing**
   - Each ACDC references a schema SAID (or equivalent).
   - Schemas should be stable, versioned, and hosted where issuers/verifiers can
     resolve them.

5. **ACDC issuance tooling**
   - Ability to assemble claims, compute SAIDs, and sign credentials.
   - Emit credentials in JSON or CESR-encoded form, depending on transport.

6. **Dossier assembly and hosting**
   - Bundle ACDCs into a single dossier (graph/DAG).
   - Host it at an `evd` URL referenced by the VVP PASSporT.
   - Support content types like `application/json+cesr` when applicable.

## Core Components

- **Issuer AID**: The KERI identifier that signs ACDCs.
- **Subject AID(s)**: Optional KERI identifiers for credential subjects.
- **Witness**: Provides receipts and key-state resolution.
- **Registry**: TEL for issuance/revocation state of ACDCs.
- **Schema registry**: Repository of schema SAIDs and definitions.
- **Dossier endpoint**: HTTP endpoint that serves the assembled dossier.

## Typical Creation Flow (High Level)

1. **Create issuer AID**
   - Inception event, witness configuration, and OOBI publication.

2. **Create or select schemas**
   - Define credential types (e.g., LE, APE, TNAlloc, delegation).
   - Publish schema definitions and capture schema SAIDs.

3. **Create a registry**
   - Establish a credential registry to anchor issuance/revocations.

4. **Issue credentials (ACDCs)**
   - Assemble claims and sign with issuer AID.
   - Anchor issuance in the registry (TEL event).

5. **Assemble dossier**
   - Collect all ACDCs needed for the claim graph.
   - Ensure edges/reference fields connect the DAG correctly.

6. **Publish dossier**
   - Host the dossier at an `evd` URL.
   - Provide OOBI access to issuer AID and registry endpoints.

## Development Notes (from Provenant)

- Do not rely on SLA-backed public witnesses for local dev or experiments.
- Running a local witness is straightforward with the `keripy` codebase:
  - install dependencies
  - build
  - run `kli witness` on a localhost port
  - the process runs until `CTRL+C`, then flushes state and stops
  - re-running typically starts with a clean state
- The `keripy` README and sample scripts have example witness commands.

## Checklist for VVP-Compatible Dossiers

- Issuer AID resolvable via OOBI.
- Witness receipts available for issuer key state at reference time.
- Each ACDC has a valid schema SAID and consistent SAID computation.
- Registry endpoints reachable for issuance/revocation checks.
- Dossier contains all required credentials for the claim graph.
- Dossier is served at a stable `evd` URL referenced by the VVP PASSporT.
