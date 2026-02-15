# VVP Common Library

## What This Package Does
Shared code installed as a package (`pip install -e common/`). Used by verifier, issuer, and SIP redirect services. Provides models, serialization, schema infrastructure, SIP message building, and utilities.

## Package Structure

```
common/
├── vvp/
│   ├── core/
│   │   ├── logging.py          # configure_logging() - structured JSON logging
│   │   └── exceptions.py       # VVPError, ACDCError, ACDCSAIDMismatch, ACDCSignatureInvalid, ACDCChainInvalid, ACDCParseError
│   ├── models/
│   │   ├── acdc.py             # ACDC dataclass + ACDCChainResult
│   │   └── dossier.py          # DossierDAG, ACDCNode, EdgeOperator, DossierWarning, ToIPWarningCode
│   ├── canonical/
│   │   ├── keri_canonical.py   # KERI canonical JSON serialization (field ordering)
│   │   ├── cesr.py             # CESR encoding/decoding utilities
│   │   ├── parser.py           # CESR stream parser
│   │   └── said.py             # SAID computation (Blake3-256)
│   ├── schema/
│   │   ├── registry.py         # Schema SAID → type mapping and lookup
│   │   ├── store.py            # Schema storage (file-based)
│   │   └── validator.py        # JSON Schema validation of ACDC attributes
│   ├── sip/
│   │   ├── models.py           # SIPRequest + SIPResponse (with vetter_status)
│   │   ├── builder.py          # SIP response builders (302, 400, 401, 403, 404, 500)
│   │   ├── parser.py           # SIP message parser
│   │   └── transport.py        # SIP UDP transport
│   └── utils/
│       └── tn_utils.py         # Telephone number normalization (E.164)
└── pyproject.toml              # Package definition
```

## Key Models

### ACDC (`models/acdc.py`)
```python
@dataclass
class ACDC:
    said: str                    # Credential SAID
    issuer: str                  # Issuer AID
    schema: str                  # Schema SAID
    attributes: dict             # 'a' section data
    edges: dict | None           # 'e' section (edge references)
    rules: dict | None           # 'r' section
    status: str | None           # Registry key
    signature: bytes | None      # CESR-encoded signature

    # Properties:
    credential_type -> str       # Inferred from schema SAID
    is_root_credential -> bool   # True if no edges
    is_bearer -> bool            # True if no issuee ('i' in attributes)
    is_subject_bound -> bool     # True if has issuee binding
    issuee_aid -> str | None     # Recipient AID from 'i' attribute

class ACDCChainResult:
    credentials: list[ACDC]      # Ordered credential chain
    root: ACDC                   # Root (trust anchor) credential
    warnings: list[str]          # Non-fatal issues
```

### Dossier (`models/dossier.py`)
```python
class EdgeOperator(Enum):        # AND, OR (edge composition)
class ToIPWarningCode(Enum):     # W001-W009 (ToIP compliance warnings)
class DossierWarning:            # Warning with code, message, credential SAID
class EdgeValidationWarning:     # Edge-level validation warning
class ACDCNode:                  # Node in credential DAG (said, acdc, children, depth)
class DossierDAG:                # Directed acyclic graph of credentials
    root: ACDCNode               # Root node
    nodes: dict[str, ACDCNode]   # SAID -> node lookup
    warnings: list[DossierWarning]
```

### SIP (`sip/models.py`)
```python
@dataclass
class SIPRequest:
    # Parsed SIP headers (From, To, Via, Call-ID, CSeq)
    # Extracted phone numbers (E.164)
    # VVP-specific headers (Identity, VVP-Identity, X-VVP-API-Key)

@dataclass
class SIPResponse:
    status_code: int
    reason: str
    headers: dict
    body: str | None
    vetter_status: str | None    # PASS | FAIL-ECC | FAIL-JURISDICTION | FAIL-ECC-JURISDICTION | INDETERMINATE
    # Generates X-VVP-Vetter-Status header when set
```

### SIP Builder (`sip/builder.py`)
Factory functions for SIP responses:
- `build_302_redirect(request, contact, identity_header, ..., vetter_status)` — VVP redirect with all headers
- `build_400_bad_request(request, reason)` — Bad request
- `build_401_unauthorized(request, reason)` — Auth required
- `build_403_forbidden(request, reason)` — Access denied
- `build_404_not_found(request, reason)` — TN not found
- `build_500_error(request, reason)` — Server error

## Key Algorithms

### SAID Computation (`canonical/said.py`)
1. Replace `d` field with placeholder string of correct length
2. Serialize to canonical form (ordered JSON, no extra whitespace)
3. Hash with Blake3-256
4. Encode as CESR-compatible Base64 string

### KERI Canonical Serialization (`canonical/keri_canonical.py`)
KERI requires specific JSON field ordering for deterministic serialization:
- Version string fields first, then `d` (SAID), `i` (issuer), `s` (schema)
- Remaining fields in spec-defined order
- No extra whitespace, UTF-8 encoding

### CESR Parsing (`canonical/cesr.py`, `parser.py`)
- Count code parsing: 2-byte hard code + variable soft code -> count
- Signature extraction: indexed signatures mapped to preceding events
- Forward compatibility: unknown codes skip gracefully

## Schema Registry (`schema/registry.py`)
Maps schema SAIDs to credential types and provides lookup:
- `get_credential_type(schema_said)` -> "LE", "QVI", "APE", "DE", "TNAlloc", etc.
- `validate_schema(data, schema_said)` -> validates attributes against JSON Schema
- Registry is additive - new schemas added without removing existing ones

## Usage
```python
from common.vvp.core.logging import configure_logging
from common.vvp.canonical.said import compute_said
from common.vvp.schema.registry import get_credential_type
from common.vvp.sip.models import SIPRequest, SIPResponse
from common.vvp.sip.builder import build_302_redirect
from common.vvp.models.acdc import ACDC, ACDCChainResult
from common.vvp.models.dossier import DossierDAG, ACDCNode
from common.vvp.utils.tn_utils import normalize_e164
```
