# OVC, VVP & KERI Glossary

This project relies on terminology from the **Open Verifiable Communications (OVC)** framework, the **Verifiable Voice Protocol (VVP)**, and the **Key Event Receipt Infrastructure (KERI)**.  
OVC is architecturally based on **KERI identifiers, event logs, and registries**, and on **ACDCs (Authentic Chained Data Containers)** for expressing verifiable assertions and proof-of-rights.

The glossary below defines terms as they are used **canonically within this project**, aligned with the KERI and ACDC specifications and the VVP draft.

All entries are ordered alphabetically. Cross-references are provided where concepts are tightly coupled.

---

## Glossary

### ACDC (Authentic Chained Data Container)
A self-describing, cryptographically bound data container used to express assertions. An ACDC binds an **Issuer AID**, a schema, a **Subject**, asserted attributes, and signatures. ACDCs are immutable; their validity and revocation status are determined externally via **Registry** state recorded in a **TEL**.

*See also:* **AID**, **Issuer**, **Subject**, **Registry**, **TEL**, **SAID**

---

### AID (Autonomic Identifier)
A KERI identifier whose authoritative state is defined by a cryptographically verifiable **Identifier Event Log (IEL)**. An AID represents cryptographic control via key state (inception, rotation, delegation, recovery), not a person, organisation, or resource. Identity, roles, and rights are expressed through credentials issued by AIDs, not embedded in the AID itself.

*See also:* **Identifier Event Log (IEL)**, **Controller**, **Issuer**, **Registry**

---

### CESR (Composable Event Streaming Representation)
A binary-to-text encoding format used for KERI events, signatures, and attachments. CESR supports pipelining and compact representation compared to conventional JSON encodings. In VVP, signatures embedded in **PASSporTs** use a specific CESR encoding profile.

*See also:* **KERI**, **PASSporT**

---

### Claim Tree
The recursive output of a VVP verifier representing the hierarchical validation status of a call. Parent claims depend on the status of child claims, which may include cryptographic checks, **IEL** resolution, and **Registry** lookups.

*See also:* **VVP**, **Proof of Rights**, **Tier 1**, **Tier 2**, **Tier 3**

---

### Controller
The entity that currently controls an **AID’s** key state, as determined by the latest valid events in the **Identifier Event Log (IEL)**. Control implies authority to issue credentials, manage **Registries**, and perform transactions associated with that AID.

*See also:* **AID**, **Identifier Event Log (IEL)**, **Issuer**

---

### Dossier
A Directed Acyclic Graph (DAG) of **ACDCs** that provides backing evidence for a call. A dossier expresses **Proof of Rights** for call origination (such as authority to use a telephone number or brand) and is referenced by a VVP **PASSporT**.

*See also:* **ACDC**, **PASSporT**, **Proof of Rights**, **VVP**

---

### Identifier Event Log (IEL)
An ordered, cryptographically verifiable log of identifier lifecycle events (including inception, rotation, interaction, and delegation) that defines the authoritative key state of an **AID** over time. IELs record identifier state only and do not record credential status or other transactional events.

*See also:* **AID**, **Controller**, **Transaction Event Log (TEL)**

---

### KERI (Key Event Receipt Infrastructure)
A decentralized identifier and event-log architecture that enables cryptographic autonomy, key rotation, delegation, and recovery without reliance on centralized trust anchors. KERI provides the foundational trust model for **OVC** and **VVP**.

*See also:* **AID**, **Identifier Event Log (IEL)**, **Transaction Event Log (TEL)**, **Registry**

---

### OOBI (Out-of-Band Introduction)
A resolvable reference (commonly a URL) used to discover KERI resources such as an **AID’s Identifier Event Log** or associated **Registries**. In VVP, the `kid` header in a **PASSporT** is an OOBI pointing to the caller’s KERI resources.

*See also:* **AID**, **Identifier Event Log (IEL)**, **PASSporT**

---

### OVC (Open Verifiable Communications)
An architectural approach to communications trust that uses verifiable credentials, cryptographic event logs, and **Proof of Rights** rather than reputation or static identity. OVC is based on **KERI** for identifiers and **ACDCs** for assertions, enabling independently verifiable evidence in communications systems.

*See also:* **KERI**, **ACDC**, **Proof of Rights**, **VVP**

---

### PASSporT (Personal Assertion Token)
A JSON Web Token (JWT) used in STIR/SHAKEN. VVP defines a specific PASSporT profile (`ppt=vvp`) in which the `kid` (Key ID) is a KERI **OOBI** and the payload references a **Dossier** containing verifiable evidence.

*See also:* **Dossier**, **OOBI**, **VVP**

---

### Proof of Rights
Cryptographic evidence that a caller is authorised to perform a specific action, such as originating a call using a particular telephone number or brand. In **OVC** and **VVP**, proof-of-rights is expressed via **ACDCs** and validated using **KERI** event logs and **Registries**.

*See also:* **ACDC**, **Registry**, **Claim Tree**, **VVP**

---

### Registry
A **TEL**-backed structure that governs the state of a class of transactions, most commonly the issuance and revocation status of credentials. Registries are controlled by **AIDs** and provide authoritative status information without modifying the credentials themselves.

*See also:* **Transaction Event Log (TEL)**, **ACDC**, **Issuer**

---

### SAID (Self-Addressing Identifier)
A content-derived identifier embedded within the data it identifies. A SAID is computed as a cryptographic hash over the canonicalized content and enables tamper-evident linking and self-verification of data structures such as **ACDCs**.

*See also:* **ACDC**, **CESR**

---

### TEL (Transaction Event Log)
A cryptographically verifiable KERI event log used to record non-identifier transactions. TELs commonly function as **Registries** for credential issuance, status, and revocation (including **ACDCs**), but are not limited to revocation use cases.

*See also:* **Registry**, **Identifier Event Log (IEL)**, **KERI**

---

### Tier 1 (Direct Verification)
Verification logic that checks the syntax and cryptographic integrity of a **PASSporT** and the structural validity of a **Dossier**, without resolving full **KERI** key history.

*See also:* **Tier 2**, **PASSporT**, **Dossier**

---

### Tier 2 (Full KERI Verification)
Verification logic that resolves complete **Identifier Event Logs (IELs)** to confirm key validity at the call timestamp and checks credential status via relevant **TEL**-backed **Registries**.

*See also:* **Tier 1**, **Tier 3**, **Identifier Event Log (IEL)**, **Registry**

---

### Tier 3 (Authorization)
High-level verification of policy and business logic, such as determining whether the caller has the right to use a specific telephone number or brand, based on verified credentials and **Registry** state.

*See also:* **Proof of Rights**, **Tier 2**, **Registry**

---

### VVP (Verifiable Voice Protocol)
A protocol that extends STIR/SHAKEN to provide cryptographically verifiable **Proof of Rights** for call origination. VVP uses **KERI** identifiers, **ACDCs**, and **Dossiers** to enable independent verification of calling authority rather than relying solely on reputation or certificate chains.

*See also:* **OVC**, **PASSporT**, **Dossier**, **Claim Tree**
