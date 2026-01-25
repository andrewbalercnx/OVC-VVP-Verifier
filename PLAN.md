# Phase 7b: CESR Parsing + KERI Canonicalization (Tier 2 Enablement)

## Problem Statement

Phase 7 implemented Tier 2 KEL resolution but with critical limitations:
- JSON-only parsing (CESR binary format rejected)
- JSON sorted-key canonicalization (not KERI-compliant)
- SAID validation disabled by default
- Witness receipt presence checked but signatures not validated

These limitations mean Tier 2 cannot verify real KERI events from production witnesses. The `TIER2_KEL_RESOLUTION_ENABLED` flag is currently `False` by default, blocking production use.

This phase removes those limitations by implementing proper CESR parsing, KERI-compliant canonicalization, SAID validation, and witness receipt signature verification.

## Spec References

From KERI specification and keripy reference implementation:
- CESR count codes define framing for attachments (`-A`, `-B`, etc.)
- Field ordering is fixed per event type (not alphabetical)
- SAID uses Blake3-256 hash of canonical "most compact form"
- Signatures are computed over canonical serialization
- Witness receipts must be validated against witness AIDs

From `VVP_Verifier_Specification_v1.5.md`:
- §5A Step 4: Key state resolution requires validating KEL chain
- §5D: Historical verification requires proper chain validation

## Current State

**Phase 7 implementation (`app/vvp/keri/`):**
- `kel_parser.py`: JSON-only parsing, CESR detection raises error
- `_compute_signing_input()`: Uses JSON sorted keys (test-only)
- `compute_said()`: Uses JSON sorted keys (test-only)
- `validate_kel_chain()`: Works but only with JSON test fixtures
- Witness receipts: Presence/threshold checked, signatures NOT validated

**Limitation:** Cannot verify real KERI events from production OOBI endpoints.

## Proposed Solution

### Approach

Implement CESR parsing and KERI canonicalization as modular components that integrate with the existing kel_parser.py infrastructure. This preserves the JSON test path while adding production-ready CESR support.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Full keripy integration | Complete implementation | Heavy dependencies, complexity | Already rejected in Phase 7 |
| Partial keripy import | Reuse existing code | Import complexity, version coupling | Tight coupling to keripy internals |
| Standalone CESR parser (chosen) | Minimal deps, clear ownership | Must implement parsing | Clean, testable, maintainable |

---

## Detailed Design

### Component 1: CESR Count Code Parser

**Purpose:** Parse CESR count codes to determine message framing and attachment types.

**Location:** `app/vvp/keri/cesr.py` (new file)

**Interface:**
```python
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple

class CountCode(Enum):
    """CESR V1 count codes for KEL attachments."""
    CONTROLLER_IDX_SIGS = "-A"    # Indexed controller signatures
    WITNESS_IDX_SIGS = "-B"       # Indexed witness signatures
    NON_TRANS_RECEIPT = "-C"      # Non-transferable receipt couples
    TRANS_RECEIPT_QUAD = "-D"     # Transferable receipt quadruples
    ATTACHMENT_GROUP = "-V"       # Attachment group
    # Add others as needed

@dataclass
class CESRAttachment:
    """Parsed CESR attachment."""
    code: CountCode
    count: int
    data: bytes

@dataclass
class CESRMessage:
    """Parsed CESR message with attachments."""
    event_bytes: bytes           # Raw JSON event bytes
    event_dict: dict            # Parsed event dictionary
    controller_sigs: List[bytes]
    witness_receipts: List[Tuple[str, bytes]]  # (witness_aid, signature)
    raw: bytes                   # Original raw bytes for debugging

def parse_cesr_stream(data: bytes) -> List[CESRMessage]:
    """Parse a CESR stream into messages with attachments.

    Args:
        data: Raw CESR byte stream.

    Returns:
        List of CESRMessage objects.

    Raises:
        ResolutionFailedError: If parsing fails.
    """
```

**Behavior:**
1. Detect CESR version string if present (`-_AAA` prefix)
2. For each message in stream:
   a. Parse JSON event (terminated by newline or attachment code)
   b. Parse attached count codes and extract signatures/receipts
3. Return structured CESRMessage objects
4. Raise `ResolutionFailedError` on malformed input

**Count Code Parsing Logic:**
```
- Read 2-4 character code prefix
- Decode count from remaining characters (base64 integer)
- Read `count` items of appropriate type based on code
- Repeat until end of attachments
```

### Component 2: KERI Canonical Serializer

**Purpose:** Serialize events in KERI field order (not alphabetical).

**Location:** `app/vvp/keri/keri_canonical.py` (new file)

**Interface:**
```python
from typing import Dict, Any

# Field orderings per event type (from keripy/src/keri/core/serdering.py)
FIELD_ORDER = {
    "icp": ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
    "rot": ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
    "ixn": ["v", "t", "d", "i", "s", "p", "a"],
    "dip": ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"],
    "drt": ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
}

def canonical_serialize(event: Dict[str, Any]) -> bytes:
    """Serialize event in KERI canonical field order.

    Args:
        event: Event dictionary with 't' field indicating type.

    Returns:
        Canonical JSON bytes (no whitespace, ordered fields).

    Raises:
        ValueError: If event type unknown or missing required fields.
    """

def most_compact_form(event: Dict[str, Any], said_field: str = "d") -> bytes:
    """Generate most compact form with placeholder SAID.

    Used for SAID computation. Replaces the SAID field with a placeholder
    of the correct length, then serializes canonically.

    Args:
        event: Event dictionary.
        said_field: Field containing SAID (usually 'd').

    Returns:
        Canonical bytes with placeholder SAID.
    """
```

**Behavior:**
1. Look up field order from `FIELD_ORDER[event["t"]]`
2. Serialize JSON with fields in specified order
3. No whitespace (compact separators)
4. UTF-8 encoding

### Component 3: SAID Computation

**Purpose:** Compute and validate Self-Addressing IDentifiers.

**Location:** Update `app/vvp/keri/kel_parser.py` (extend existing `compute_said`)

**Interface:**
```python
def compute_said_canonical(event: Dict[str, Any], algorithm: str = "blake3-256") -> str:
    """Compute SAID using KERI canonical serialization.

    Steps:
    1. Create most compact form with placeholder
    2. Hash with Blake3-256 (required in production)
    3. Encode with derivation code prefix

    Args:
        event: Event dictionary.
        algorithm: Hash algorithm (default blake3-256).

    Returns:
        SAID string with derivation code prefix (e.g., "E...").

    Raises:
        ImportError: If blake3 not available in production mode.
    """

def validate_event_said(event: Dict[str, Any], use_canonical: bool = True) -> None:
    """Validate that event's 'd' field matches computed SAID.

    Args:
        event: Event dictionary.
        use_canonical: If True, use KERI canonical serialization.
                      If False, use JSON sorted-keys (test mode only).

    Raises:
        KELChainInvalidError: If SAID doesn't match.
    """
```

**Blake3 Requirement:**
- Blake3 is REQUIRED in production (not optional)
- SHA256 fallback allowed ONLY when `_allow_test_mode=True`
- Raise `ImportError` if blake3 unavailable and not in test mode

### Component 4: Updated Chain Validation

**Purpose:** Update `validate_kel_chain()` to use canonical serialization.

**Location:** Update `app/vvp/keri/kel_parser.py`

**Changes:**
1. `_compute_signing_input()` → uses `canonical_serialize()` for CESR inputs
2. `validate_kel_chain()` → requires SAID validation for CESR inputs
3. Keep JSON sorted-keys path for backward compatibility with tests (guarded by flag)

```python
def _compute_signing_input(event: KELEvent, use_canonical: bool = False) -> bytes:
    """Compute signing input for signature verification.

    Args:
        event: The KELEvent to compute signing input for.
        use_canonical: If True, use KERI canonical serialization.
                      If False, use JSON sorted-keys (test mode only).

    Returns:
        Bytes that were signed.
    """
```

### Component 5: OOBI Content Type Routing

**Purpose:** Route CESR vs JSON based on content-type header.

**Location:** Update `app/vvp/keri/oobi.py` and `kel_parser.py`

**Changes:**
1. `dereference_oobi()` stores content-type in `OOBIResult`
2. `parse_kel_stream()` accepts `content_type` parameter
3. Route to CESR parser for `application/json+cesr`
4. JSON parser ONLY allowed when `_allow_test_mode=True` (strictly non-production)

```python
@dataclass
class OOBIResult:
    aid: str
    kel_data: bytes
    witnesses: List[str]
    content_type: str = "application/json"  # New field
    error: Optional[str] = None

def parse_kel_stream(
    kel_data: bytes,
    content_type: str = "application/json",
    allow_json_only: bool = False  # Default changed to False
) -> List[KELEvent]:
    """Parse KEL stream based on content type.

    Args:
        kel_data: Raw KEL data.
        content_type: Content-Type from OOBI response.
        allow_json_only: Allow JSON when CESR expected (test mode only).

    Returns:
        List of parsed KELEvent objects.

    Raises:
        ResolutionFailedError: If JSON used without test mode flag.
    """
```

### Component 6: Witness Receipt Signature Validation

**Purpose:** Validate witness signatures against witness AIDs (not just presence/threshold).

**Location:** Update `app/vvp/keri/kel_parser.py`

**Interface:**
```python
@dataclass
class WitnessReceipt:
    witness_aid: str
    signature: bytes
    timestamp: Optional[datetime] = None
    public_key: Optional[bytes] = None  # Resolved from witness AID

def validate_witness_receipts(
    event: KELEvent,
    signing_input: bytes,
    min_threshold: int
) -> None:
    """Validate witness receipt signatures against event.

    For each witness receipt:
    1. Resolve witness AID to public key
    2. Verify signature against signing input
    3. Count valid signatures

    Args:
        event: The KELEvent with witness receipts.
        signing_input: Canonical bytes that were signed.
        min_threshold: Minimum valid signatures required.

    Raises:
        KELChainInvalidError: If insufficient valid witness signatures.
        ResolutionFailedError: If witness AIDs cannot be resolved.
    """
```

**Behavior:**
1. For each `WitnessReceipt` in `event.witness_receipts`:
   a. Parse witness AID to extract public key (using existing `_decode_keri_key()`)
   b. Verify signature against `signing_input`
   c. Track valid signature count
2. If valid count < `min_threshold`, raise `KELChainInvalidError`
3. If witness AID cannot be parsed, raise `ResolutionFailedError` (INDETERMINATE)

**Note:** Witness AIDs are typically non-transferable (B-prefix), so we can extract the key directly without KEL resolution.

---

## Data Flow

```
OOBI Response (Content-Type: application/json+cesr)
        │
        ▼
┌──────────────────┐
│  CESR Parser     │ ──────► Parse count codes, extract events + attachments
│  (cesr.py)       │
└────────┬─────────┘
         │ List[CESRMessage]
         ▼
┌──────────────────┐
│ Canonical        │ ──────► Serialize in KERI field order
│ Serializer       │
└────────┬─────────┘
         │ Canonical bytes
         ▼
┌──────────────────┐
│ SAID Validator   │ ──────► Verify d field matches Blake3 hash
└────────┬─────────┘
         │ Validated events
         ▼
┌──────────────────┐
│ Chain Validator  │ ──────► Verify controller signatures
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│Witness Validator │ ──────► Verify witness receipt signatures
└────────┬─────────┘
         │ KELEvent list
         ▼
   Existing resolver flow
```

---

## Error Handling

| Error Condition | Error Type | Claim Status |
|-----------------|------------|--------------|
| Invalid CESR count code | ResolutionFailedError | INDETERMINATE |
| Truncated CESR stream | ResolutionFailedError | INDETERMINATE |
| SAID mismatch | KELChainInvalidError | INVALID |
| Signature mismatch (canonical) | KELChainInvalidError | INVALID |
| Unknown event type | ResolutionFailedError | INDETERMINATE |
| Witness AID resolution failed | ResolutionFailedError | INDETERMINATE |
| Insufficient valid witness sigs | KELChainInvalidError | INVALID |
| Blake3 unavailable (production) | ImportError | INDETERMINATE |
| JSON content without test mode | ResolutionFailedError | INDETERMINATE |

---

## Test Strategy

### 1. Unit Tests for CESR Parser (`tests/test_cesr_parser.py`)
- Parse valid CESR stream with controller signatures
- Parse CESR stream with witness receipts
- Handle truncated/invalid count codes
- Handle empty stream

### 2. Unit Tests for Canonicalization (`tests/test_canonicalization.py`)
- ICP event canonical order matches expected
- ROT event canonical order matches expected
- IXN event canonical order matches expected
- Unknown event type raises error

### 3. Canonical Verification Against keripy (`tests/test_canonical_keripy_compat.py`)
**NEW: Addresses reviewer requirement #1**

Compare our `canonical_serialize()` output against keripy's serdering output for all fixture event types:

```python
def test_icp_canonical_matches_keripy():
    """Verify ICP canonical output matches keripy serdering."""
    # Load ICP fixture generated by keripy
    fixture = load_fixture("icp_keripy.json")

    # Get expected canonical bytes from keripy output
    expected = fixture["canonical_bytes"]

    # Compute using our implementation
    actual = canonical_serialize(fixture["event"])

    assert actual == expected, "ICP canonical mismatch with keripy"

def test_rot_canonical_matches_keripy():
    """Verify ROT canonical output matches keripy serdering."""
    # ... similar

def test_ixn_canonical_matches_keripy():
    """Verify IXN canonical output matches keripy serdering."""
    # ... similar
```

**Fixture Generation Script:**
Create `scripts/generate_keripy_fixtures.py` that uses keripy's serdering to generate canonical byte vectors:
```python
from keri.core.serdering import SerderKERI
# Generate events and capture canonical bytes for each event type
```

### 4. Unit Tests for SAID (`tests/test_said_canonical.py`)
- SAID computation matches known vectors
- SAID validation passes for correct digest
- SAID validation fails for incorrect digest
- Most compact form generates correct placeholder
- Blake3 required in production mode (ImportError if missing)

### 5. Unit Tests for Witness Validation (`tests/test_witness_validation.py`)
**NEW: Addresses reviewer requirement #2**

- Valid witness signatures pass threshold
- Invalid witness signatures fail validation
- Missing witness signatures fail threshold
- Witness AID parsing extracts correct key
- Non-transferable witness AIDs (B-prefix) work correctly

### 6. Integration Tests (`tests/test_kel_cesr_integration.py`)
- End-to-end CESR KEL parsing and validation
- Signature verification with canonical bytes
- Chain validation with real CESR fixtures
- Witness receipt validation with CESR fixtures

### 7. Fixtures (`tests/fixtures/keri/`)
- `icp_cesr.txt` - Inception event with signatures
- `rot_cesr.txt` - Rotation event with signatures
- `kel_stream.txt` - Full KEL stream (icp + rot + ixn)
- `kel_with_witnesses.txt` - KEL with witness receipts
- `icp_keripy.json` - keripy-generated ICP with canonical bytes
- `rot_keripy.json` - keripy-generated ROT with canonical bytes
- `ixn_keripy.json` - keripy-generated IXN with canonical bytes

**Fixture Generation:**
Use keripy to generate all fixtures (authoritative reference, prevents serialization drift).

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `app/vvp/keri/cesr.py` | Create | CESR count code parser |
| `app/vvp/keri/keri_canonical.py` | Create | KERI canonical serialization |
| `app/vvp/keri/kel_parser.py` | Modify | Integrate CESR + canonical + witness validation |
| `app/vvp/keri/oobi.py` | Modify | Content-type routing |
| `app/core/config.py` | Modify | Update feature flag docs |
| `tests/test_cesr_parser.py` | Create | CESR parser tests |
| `tests/test_canonicalization.py` | Create | Canonicalization tests |
| `tests/test_canonical_keripy_compat.py` | Create | keripy compatibility verification |
| `tests/test_said_canonical.py` | Create | SAID tests |
| `tests/test_witness_validation.py` | Create | Witness receipt validation tests |
| `tests/test_kel_cesr_integration.py` | Create | Integration tests |
| `tests/fixtures/keri/` | Create | CESR test fixtures |
| `scripts/generate_keripy_fixtures.py` | Create | Fixture generation script |

---

## Implementation Order

1. **Generate keripy Fixtures** - Create authoritative test vectors first
2. **Canonical Serializer** - KERI field ordering with keripy verification
3. **SAID Computation** - Using canonical bytes, Blake3 required
4. **CESR Parser** - Parse count codes and extract attachments
5. **Witness Receipt Validation** - Validate signatures against AIDs
6. **Chain Validation** - Update to use canonical path + witness validation
7. **OOBI Routing** - Content-type based parsing, JSON strictly test-only
8. **Integration Tests** - End-to-end validation
9. **Enable Feature Flag** - Flip `TIER2_KEL_RESOLUTION_ENABLED` to True

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| CESR parsing complexity | Medium | High | Use keripy as authoritative reference |
| Field ordering errors | Low | High | Validate against keripy fixtures explicitly |
| Blake3 availability | Low | Medium | Require in production, fail clearly if missing |
| Backward compatibility | Low | Medium | Keep JSON test path intact but strictly gated |
| Witness AID resolution | Low | Medium | Support common non-transferable prefixes |

---

## Exit Criteria

- [ ] CESR parser handles all required count codes
- [ ] Canonical serialization matches keripy output (verified by tests)
- [ ] SAID validation works with canonical bytes
- [ ] Witness receipt signatures validated against AIDs
- [ ] Chain validation passes with real CESR fixtures
- [ ] All existing tests still pass
- [ ] New tests provide >90% coverage of new code
- [ ] Blake3 required in production (ImportError if missing)
- [ ] JSON parsing strictly gated behind test mode
- [ ] `TIER2_KEL_RESOLUTION_ENABLED` can be safely set to True

---

## Resolved Questions (per Reviewer)

1. **Fixture generation**: Use keripy to generate fixtures. It's the authoritative reference and prevents subtle serialization drift.

2. **Blake3 dependency**: Require blake3 in production. SHA256 fallback is test-only and explicitly non-compliant.

3. **Witness receipt validation**: Yes—validate witness signatures against witness AIDs in this phase. This is required for production-grade key state resolution.

---

## Revision 1 (Response to CHANGES_REQUESTED)

### Changes Made

| Finding | Resolution |
|---------|------------|
| [Medium] No verification step proving canonical alignment with keripy | Added explicit keripy compatibility tests in `tests/test_canonical_keripy_compat.py` that compare our output against keripy's serdering for all event types |
| [Medium] Witness receipt signatures not validated | Added Component 6: Witness Receipt Signature Validation with full implementation details |

### Additional Changes

1. **Blake3 now required in production** - SHA256 fallback only in test mode
2. **JSON parsing strictly gated** - `allow_json_only` default changed to `False`
3. **Added fixture generation script** - `scripts/generate_keripy_fixtures.py`
4. **Added keripy compatibility test file** - `tests/test_canonical_keripy_compat.py`
5. **Added witness validation test file** - `tests/test_witness_validation.py`
6. **Updated implementation order** - Generate fixtures first, then build against them
