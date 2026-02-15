# VVP Data Models Reference

## Verifier Models (`services/verifier/app/vvp/`)

### api_models.py - Request/Response Models

#### Enums
```python
class ClaimStatus(str, Enum):
    VALID = "VALID"                # Proven by evidence
    INVALID = "INVALID"            # Contradicted by evidence
    INDETERMINATE = "INDETERMINATE"  # Insufficient evidence
```

#### Request Models
```python
class SipContext(BaseModel):
    from_uri: str                  # SIP From URI
    to_uri: str                    # SIP To URI
    invite_time: str               # RFC3339 timestamp
    cseq: Optional[int] = None    # CSeq number (callee verification)

class CallContext(BaseModel):
    call_id: str                   # Call identifier
    received_at: str               # RFC3339 timestamp
    sip: Optional[SipContext]      # SIP context for alignment

class VerifyRequest(BaseModel):
    passport_jwt: str              # PASSporT JWT string
    context: CallContext           # Call context (required)

class VerifyCalleeRequest(BaseModel):
    passport_jwt: str              # Callee's PASSporT
    context: CallContext           # Must include call_id + sip.cseq
    caller_passport_jwt: Optional[str]  # For goal overlap check
```

#### Response Models
```python
class ChildLink(BaseModel):
    required: bool                 # Is this child required for parent validity?
    node: ClaimNode                # The child claim node

class ClaimNode(BaseModel):
    name: str                      # Claim name (e.g., "passport_verified")
    status: ClaimStatus            # VALID/INVALID/INDETERMINATE
    reasons: List[str]             # Explanation strings
    evidence: List[str]            # SAIDs or references
    children: List[ChildLink]      # Child claims

class ErrorDetail(BaseModel):
    code: str                      # ErrorCode constant
    message: str                   # Human-readable message
    recoverable: bool              # Can be retried?

class VerifyResponse(BaseModel):
    request_id: str                # UUID
    overall_status: ClaimStatus    # Final status
    claims: Optional[List[ClaimNode]]
    errors: Optional[List[ErrorDetail]]
    has_variant_limitations: bool  # Compact/partial ACDCs present?
    delegation_chain: Optional[DelegationChainResponse]
    signer_aid: Optional[str]
    toip_warnings: Optional[List[ToIPWarningDetail]]
    issuer_identities: Optional[Dict[str, IssuerIdentityInfo]]
    vetter_constraints: Optional[Dict[str, VetterConstraintInfo]]
    brand_name: Optional[str]     # From PASSporT card claim
    brand_logo_url: Optional[str] # From PASSporT card claim

class DelegationChainResponse(BaseModel):
    chain: List[DelegationNodeResponse]
    depth: int
    root_aid: Optional[str]
    is_valid: bool
    errors: List[str]

class VetterConstraintInfo(BaseModel):
    credential_said: str
    credential_type: str           # "TN", "Identity", "Brand"
    constraint_type: str           # "ecc" or "jurisdiction"
    target_value: str              # e.g., "44" for ECC
    allowed_values: List[str]
    is_authorized: bool
    reason: str
```

### exceptions.py - Domain Exceptions
```python
class VVPIdentityError(Exception):
    code: str    # ErrorCode constant
    message: str
    # Factory methods: .missing(), .invalid(reason)

class PassportError(Exception):
    code: str
    message: str
    # Factory methods: .missing(), .parse_failed(reason),
    #                  .forbidden_alg(alg), .expired(reason)
```

### acdc/acdc.py - ACDC Model
```python
@dataclass
class ACDC:
    said: str                      # Content-derived identifier
    issuer: str                    # Issuer AID
    issuee: Optional[str]         # Subject AID
    schema_said: str              # Schema reference
    attributes: dict              # Attribute block
    edges: dict                   # Edge block (links to other ACDCs)
    raw: dict                     # Original JSON
    variant: str                  # "full", "compact", "partial"
    registry_said: Optional[str]  # Registry for revocation
    credential_type: str          # Inferred: "LE", "APE", "DE", "TNAlloc", etc.
```

### dossier/models.py - Dossier Models
```python
@dataclass
class ACDCNode:
    acdc: ACDC
    signatures: list              # Attached signatures
    parents: List[str]            # SAIDs of parent credentials
    children: List[str]           # SAIDs of child credentials

class DossierDAG:
    nodes: Dict[str, ACDCNode]    # SAID → node
    root: Optional[ACDCNode]      # Single root node
    edges: List[Tuple[str, str]]  # (from_said, to_said)
```

---

## Issuer Models

### db/models.py - SQLAlchemy Database Models
```python
class Organization(Base):
    id: UUID                       # Primary key
    name: str                      # Organization name
    lei: Optional[str]             # Legal Entity Identifier
    aid: Optional[str]             # KERI AID
    le_credential_said: Optional[str]  # Auto-issued LE credential
    vetter_certification_said: Optional[str]  # Active VetterCert SAID (Sprint 61)
    status: str                    # "active", "suspended"
    created_at: datetime
    updated_at: datetime

class OrgAPIKey(Base):
    id: UUID
    organization_id: UUID          # FK to Organization
    key_hash: str                  # Hashed API key
    key_prefix: str                # First 8 chars for identification
    name: str                      # Human-readable name
    roles: str                     # JSON list of roles
    is_active: bool
    created_at: datetime

class Credential(Base):
    said: str                      # Primary key (SAID)
    organization_id: UUID          # FK to Organization
    schema_said: str
    credential_type: str
    issuer_aid: str
    issuee_aid: Optional[str]
    registry_key: str
    status: str                    # "issued", "revoked"
    raw_json: str                  # Full credential JSON

class Dossier(Base):
    id: UUID
    organization_id: UUID
    root_credential_said: str
    format: str                    # "cesr" or "json"
    content: bytes                 # Serialized dossier
    credential_count: int

class TNMapping(Base):
    id: UUID
    organization_id: UUID
    telephone_number: str          # E.164 format
    dossier_id: UUID               # FK to Dossier
    signing_identity_aid: str      # AID for signing
    enabled: bool
    brand_name: Optional[str]
    brand_logo_url: Optional[str]

class User(Base):
    id: UUID
    email: str
    password_hash: str
    name: str
    roles: str                     # JSON list
    organization_id: Optional[UUID]
    is_active: bool

class DossierOspAssociation(Base):   # Sprint 63
    """Administrative record: which OSP org can reference which dossier.
    Visibility only — does NOT gate TN mapping authorization."""
    __tablename__ = "dossier_osp_associations"
    id: int                        # Primary key, autoincrement
    dossier_said: str(44)          # Dossier credential SAID
    owner_org_id: UUID             # FK → organizations.id (AP), CASCADE
    osp_org_id: UUID               # FK → organizations.id (OSP), CASCADE, indexed
    created_at: datetime
    # Unique constraint: (dossier_said, osp_org_id)

class ManagedCredential(Base):        # Tracks credential ownership
    __tablename__ = "managed_credentials"
    said: str(44)                  # Primary key (credential SAID)
    organization_id: UUID          # FK → organizations.id
    schema_said: str(44)           # Schema SAID
    issuer_aid: str(44)            # Issuer AID
    created_at: datetime

class MockVLEIState(Base):            # Persists mock vLEI infrastructure state
    __tablename__ = "mock_vlei_state"
    id: int                        # Primary key
    gleif_aid: str(44)             # Mock GLEIF root AID
    qvi_aid: str(44)              # Mock QVI AID
    gleif_registry_key: str(44)
    qvi_registry_key: str(44)
    gsma_aid: Optional[str(44)]    # Mock GSMA AID (Sprint 61)
    gsma_registry_key: Optional[str(44)]  # Mock GSMA registry (Sprint 61)
    initialized_at: datetime
```

### api/models.py - Issuer API Models
Request/response Pydantic models for all issuer endpoints. Key models:

```python
class CreateIdentityRequest(BaseModel):
    name: str
    witness_urls: Optional[List[str]]

class IssueCredentialRequest(BaseModel):
    schema_said: str
    issuer_aid: str
    issuee_aid: Optional[str]
    registry_key: str
    attributes: dict
    edges: Optional[dict]
    organization_id: Optional[str]  # Cross-org issuance (Sprint 61)

class CreateTNMappingRequest(BaseModel):
    telephone_number: str          # E.164
    dossier_id: str
    signing_identity_aid: str
    brand_name: Optional[str]
    brand_logo_url: Optional[str]

class TNLookupRequest(BaseModel):
    telephone_number: str          # E.164 format

class CreateOrganizationRequest(BaseModel):
    name: str
    lei: Optional[str]

# Sprint 63 — Dossier Creation Wizard
class CreateDossierRequest(BaseModel):
    owner_org_id: str              # AP organization ID
    name: Optional[str]            # Dossier name (max 255)
    edges: dict[str, str]          # {edge_name: credential_SAID}
    osp_org_id: Optional[str]      # OSP org to associate

class CreateDossierResponse(BaseModel):
    dossier_said: str
    issuer_aid: str
    schema_said: str
    edge_count: int
    name: Optional[str]
    osp_org_id: Optional[str]
    dossier_url: str
    publish_results: Optional[list[WitnessPublishResult]]

class OrganizationNameResponse(BaseModel):
    id: str
    name: str
    aid: Optional[str]             # Included only when purpose=ap (Sprint 65)

class OrganizationNameListResponse(BaseModel):
    count: int
    organizations: list[OrganizationNameResponse]

class AssociatedDossierEntry(BaseModel):
    dossier_said: str
    owner_org_id: str
    owner_org_name: str
    osp_org_id: str
    created_at: str

class AssociatedDossierListResponse(BaseModel):
    count: int
    associations: list[AssociatedDossierEntry]

# Sprint 65 — Dossier Readiness Assessment
class DossierSlotStatus(BaseModel):
    edge: str                      # Edge name (vetting, alloc, tnalloc, etc.)
    label: str                     # Human-readable label
    required: bool                 # Is this slot required?
    schema_constraint: Optional[str]  # Required schema SAID (if constrained)
    available_count: int           # Count of valid, available credentials
    total_count: int               # Total credentials matching schema
    status: str                    # "ready", "missing", "invalid", "optional_missing", "optional_unconstrained"

class DossierReadinessResponse(BaseModel):
    org_id: str                    # Organization UUID
    org_name: str                  # Organization name
    ready: bool                    # Overall readiness (all required slots ready)
    slots: list[DossierSlotStatus] # Per-slot assessment
    blocking_reason: Optional[str] # Why not ready (if ready=False)

# Sprint 61 — Vetter Certification
class VetterCertificationCreateRequest(BaseModel):
    organization_id: str           # Target org UUID
    ecc_targets: list[str]         # E.164 country codes (validated against VALID_ECC_CODES)
    jurisdiction_targets: list[str]  # ISO 3166-1 alpha-3 codes (validated against VALID_JURISDICTION_CODES)
    name: str                      # Vetter name (1-255 chars)
    certification_expiry: Optional[str]  # ISO8601 UTC, alias "certificationExpiry"

class VetterCertificationResponse(BaseModel):
    said: str
    issuer_aid: str                # Mock GSMA AID
    vetter_aid: str                # Org AID
    organization_id: str
    organization_name: str
    ecc_targets: list[str]
    jurisdiction_targets: list[str]
    name: str
    certification_expiry: Optional[str]  # Alias "certificationExpiry"
    status: str                    # "issued" or "revoked"
    created_at: str

class VetterCertificationListResponse(BaseModel):
    certifications: list[VetterCertificationResponse]
    count: int

class OrganizationConstraintsResponse(BaseModel):
    organization_id: str
    organization_name: str
    vetter_certification_said: Optional[str]
    ecc_targets: Optional[list[str]]
    jurisdiction_targets: Optional[list[str]]
    certification_status: Optional[str]
    certification_expiry: Optional[str]
```

---

## Common Models (`common/`)

### vvp/sip/models.py - Shared SIP Models
```python
class SIPRequest(BaseModel):
    method: str                    # INVITE, BYE, etc.
    request_uri: str               # Target URI
    sip_version: str               # SIP/2.0
    headers: Dict[str, str]        # All headers
    body: Optional[str]            # SDP body
    raw: bytes                     # Original bytes
    from_tn: Optional[str]         # Extracted caller TN
    to_tn: Optional[str]           # Extracted callee TN
    call_id: Optional[str]
    cseq: Optional[str]
    via: Optional[str]
    api_key: Optional[str]         # X-VVP-API-Key
    identity_header: Optional[str] # Identity (PASSporT)
    vvp_identity_header: Optional[str]  # VVP-Identity
```

### vvp/canonical/ - Serialization
- `said.py`: SAID computation (Blake3-256)
- `cesr.py`: CESR encoding/decoding
- `parser.py`: CESR stream parsing
- `keri_canonical.py`: KERI canonical JSON serialization

### vvp/schema/ - Schema Infrastructure
- `registry.py`: Schema SAID → credential type mapping
- `store.py`: Schema storage and retrieval
- `validator.py`: JSON Schema validation of ACDC attributes

---

## Error Code Registry

See `services/verifier/app/vvp/api_models.py:ErrorCode` for the complete registry.

Key error codes by layer:
- **Protocol**: VVP_IDENTITY_*, PASSPORT_*, CONTEXT_MISMATCH, DIALOG_MISMATCH
- **Crypto**: PASSPORT_SIG_INVALID, PASSPORT_FORBIDDEN_ALG, ACDC_SAID_MISMATCH
- **Evidence**: DOSSIER_*, CREDENTIAL_REVOKED, BRAND_CREDENTIAL_INVALID
- **KERI**: KERI_RESOLUTION_FAILED, KERI_STATE_INVALID
- **Authorization**: AUTHORIZATION_FAILED, TN_RIGHTS_INVALID
- **Vetter**: VETTER_ECC_UNAUTHORIZED, VETTER_JURISDICTION_UNAUTHORIZED
- **Internal**: INTERNAL_ERROR
