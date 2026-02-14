# Glossary — KERI/ACDC/vLEI/VVP Terms

| Term | Expansion | Definition |
|------|-----------|------------|
| **ACDC** | Authentic Chained Data Container | Verifiable credential format using KERI. Forms DAGs via edges. |
| **AID** | Autonomic Identifier | Self-certifying identifier derived from public key material. |
| **AP** | Accountable Party | Entity that signs the dossier. Dossier's `i` field = AP's AID. |
| **APE** | Auth Phone Entity | Credential authorizing an entity for phone operations. |
| **CESR** | Composable Event Streaming Representation | Binary/text encoding for KERI events and signatures. |
| **CVD** | Compact Verifiable Document | ACDC with no issuee — asserted to the world. Dossiers are CVDs. |
| **DAG** | Directed Acyclic Graph | Graph of ACDCs connected by edges (no cycles). |
| **DE** | Delegate Entity | Credential delegating authority to a sub-entity. |
| **DI2I** | Delegated-Issuer-to-Issuee | Edge operator allowing delegated issuers. |
| **ECR** | Engagement Context Role | vLEI role credential for functional contexts. |
| **GCD** | General Cooperative Delegation | Schema used for alloc and delsig edges. |
| **GLEIF** | Global Legal Entity Identifier Foundation | Root of trust for the vLEI ecosystem. |
| **I2I** | Issuer-to-Issuee | Default edge operator: child issuer must be parent issuee. |
| **IXN** | Interaction Event | KERI event that anchors data without changing keys. |
| **KAACE** | KERI Agreement Algorithm for Control Establishment | Witness consensus mechanism. |
| **KEL** | Key Event Log | Append-only log of key events for an AID. |
| **KERL** | Key Event Receipt Log | KEL + witness receipts. |
| **LE** | Legal Entity | vLEI credential identifying a legal entity. |
| **LEI** | Legal Entity Identifier | ISO 17442 identifier for legal entities. |
| **NI2I** | Not-Issuer-to-Issuee | Permissive edge operator: no relationship required. |
| **OOBI** | Out-of-Band Introduction | URL that associates an AID with a network endpoint. |
| **OOR** | Official Organizational Role | vLEI role credential for official positions. |
| **OP** | Originating Party | Entity that signs PASSporTs. Authorized via delsig. |
| **PASSporT** | Personal Assertion Token | RFC 8225 JWT for call attestation. |
| **QVI** | Qualified vLEI Issuer | Entity authorized by GLEIF to issue LE credentials. |
| **RTU** | Right to Use | Alternative name for TN Allocation schema. |
| **SAID** | Self-Addressing Identifier | Content hash embedded within the data it identifies. |
| **TEL** | Transaction Event Log | Tracks credential issuance/revocation. |
| **TN** | Telephone Number | Phone number subject to VVP authorization. |
| **TNAlloc** | TN Allocation | Credential allocating telephone numbers to an entity. |
| **TOAD** | Threshold of Accountable Duplicity | Minimum witness receipts required. |
| **VVP** | Verified Voice Protocol | Protocol extending STIR/SHAKEN with KERI/ACDC. |
| **vLEI** | Verifiable Legal Entity Identifier | Cryptographic credential ecosystem governed by GLEIF. |
