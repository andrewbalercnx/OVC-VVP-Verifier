# Verifiable Voice Protocol (VVP) Specification Analysis

**Source Document:** [draft-hardman-verifiable-voice-protocol-05](https://datatracker.ietf.org/doc/html/draft-hardman-verifiable-voice-protocol-05)

## 1. Introduction
**Type: COMMENTARY**
Provides background on the problem space (trust gaps in telephony), limitations of existing solutions (SHAKEN, etc.), and the high-level goals of VVP.

## 2. Conventions and Definitions
**Type: COMMENTARY**
Defines standard BCP 14 interpretations for keywords (MUST, SHOULD, MAY). While this defines how requirements are expressed, the section itself is explanatory.

## 3. Overview
**Type: COMMENTARY**
Describes the fundamental workflow:
- Pre-configuration of dossiers (stable evidence).
- Caller sharing evidence via ephemeral VVP Passports in SIP Identity headers.
- Callee sharing evidence via SDP attributes (optional direction).
- Verification by intermediaries or endpoints.

### 3.1 Roles
**Type: COMMENTARY**
Defines key actors:
- **Callee:** Receiver of the SIP INVITE.
- **Originating Party (OP):** Party controlling the initial SBC; creates the VVP passport. Note: Distinguishes OP from the "Caller" (handset operator).

### 3.2 Lifecycle
**Type: COMMENTARY**
Describes the sequence of events from dossier creation to call termination.

## 4. Citing
### 4.1 Citing the AP's dossier (Caller Identification)
**Type: REQUIREMENT**
Mandatory for VVP implementation (Caller Verification flow).
- **OP Requirements:**
    - MUST generate a valid STIR-compatible VVP Passport.
    - MUST pass this passport in the `Identity` header of the SIP INVITE.
    - If using DTLS-SRTP, the INVITE MUST contain the DTLS fingerprint attribute.
- **Passport Content:**
    - `kid` header MUST contain the OOBI of the OP.
    - `evd` claim MUST reference the AP's dossier.
    - `iat` and `exp` claims are used for timing.

### 4.2 Citing a callee's dossier
**Type: OPTIONAL**
Implementations MAY support callee verification.
- **If Implemented:**
    - Callee MUST curate a dossier (identical schema to caller).
    - Citation MUST be conveyed via `a=callee-passport:X` attribute in SDP body of 200 OK response (and MAY use 180 Ringing).
    - Passport MUST use `;type=vvp` suffix.
    - **Header/Claim Constraints:**
        - `kid` contains OOBI of callee.
        - `call-id` and `cseq` MUST match the preceding SIP INVITE.
        - `iat` MUST be present (callee system clock).
        - `evd` MUST be present (callee dossier OOBI).
        - `exp` MAY be present.

## 5. Verifying
### 5.1 Verifying the caller
**Type: REQUIREMENT**
Mandatory for a VVP Verifier implementation.
- Verifier SHOULD use an algorithm equivalent to the specified 8 steps (optimizations allowed if guarantees are preserved):
    1.  **Timing:** Analyze `iat` and `exp` (recommend 30s tolerance).
    2.  **Context:** Confirm `orig`, `dest`, `iat` match SIP metadata.
    3.  **Key Identification:** Extract `kid` header.
    4.  **Key State:** Fetch OP key state at reference time from OOBI (cache allowed).
    5.  **Signature:** Verify passport signature against OP public key.
    6.  **Evidence:** Extract `evd` field.
    7.  **Dossier Cache:** Lookup dossier by SAID.
    8.  **Dossier Validation:** If not cached, validate the dossier graph (signatures, ACDC issuers, KEL witness checks).

### 5.2 Verifying the callee
**Type: OPTIONAL**
Corresponding verification logic for the optional callee flow.
- **If Implemented:**
    - MUST use algorithm equivalent to the specified 14 steps, including:
        - Matching `call-id`/`cseq` to INVITE.
        - Verifying callee key state/signature.
        - Validating dossier and revocation status.
        - Checking TN rights (`TNAlloc`) and Brand credentials.
        - Business logic (goal overlap, hours, geos).

### 5.3 Planning for efficiency
**Type: COMMENTARY**
Discusses architectural benefits of VVP (caching, decentralization) and performance strategies.

### 5.4 Historical analysis
**Type: COMMENTARY**
Describes the capability to verify passports at an arbitrary past time ("then" vs "now") using KEL history.

## 6. Security Considerations
**Type: REQUIREMENT**
Contains normative security mandates.
- **Identity:** Parties issuing credentials MUST be identified with AIDs (KERI) using witnesses.
- **Credential Format:** Issuers MUST use ACDCs (Authentic Chained Data Containers) signed by their AID (not raw keys).
- **Multi-sig:** Issuers SHOULD employ threshold-based multi-signature schemes.
- **Policies (Strongly Recommended):**
    1. Aggressive passport timeouts (e.g., 30s).
    2. High-availability witnesses.
    3. Timely revocations.
    4. Low-latency propagation by watchers.

## 7. IANA Considerations
**Type: COMMENTARY**
Registration details.

## 8. References
**Type: COMMENTARY**
Normative and Informative references.
