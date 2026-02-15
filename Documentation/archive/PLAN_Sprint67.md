# Sprint 67: Trust Anchor Admin & Credential Issuance UI

## Problem Statement

Trust-chain entities (GLEIF, QVI, GSMA) exist as standalone KERI identities managed by `MockVLEIManager` but are invisible to the Organization UI. There is no way to:
- See GLEIF/QVI/GSMA in the organizations list
- Create admin users for these organizations
- Log in "as GSMA" and issue VetterCertifications through the UI
- Restrict which credential schemas an organization is authorized to issue

This sprint promotes trust anchors to first-class organizations and adds schema-scoped credential issuance, making the system fully administrable through the web UI.

## Current State

| Area | Current State | Gap |
|------|---------------|-----|
| Organization model | `Organization` in `app/db/models.py` — id, name, pseudo_lei, aid, le_credential_said, registry_key, vetter_certification_said, enabled | No `org_type` field to distinguish trust anchors from regular orgs |
| MockVLEIManager | Creates KERI identities for GLEIF/QVI/GSMA, persists state in `MockVLEIState` — gleif_aid, qvi_aid, gsma_aid, registry keys, credential SAIDs | Does NOT create `Organization` DB records for trust anchors |
| Session/Principal | `Principal` dataclass — key_id, name, roles, organization_id. `Session` — session_id, key_id, principal, created_at, expires_at | No `active_org_id` for org switching |
| VetterCert issuance | `vetter/service.py:issue_vetter_certification()` calls `mock_vlei.issue_vetter_certification()` which uses hard-coded mock-gsma registry name | No org-type validation, hard-coded to mock-gsma |
| Credential issuance | `POST /credential/issue` resolves org context from principal or request body, checks VetterCert edge for extended schemas | No schema authorization by org type |
| Schema store | 14 embedded schemas with SAIDs, `GET /schema` returns all | No filtering by org type |
| Organizations API | CRUD on orgs (create, list, get, update). `OrganizationResponse` includes all fields but no `org_type` | No type field |
| Organization UI | `organizations.html` — card grid with org fields and status badge | No type badges, no detail page |

## Proposed Solution

### Phase 1: Organization Type Model

**Why:** Without `org_type`, there's no way to programmatically distinguish trust anchors from regular organizations or enforce schema authorization.

#### 1.1 Add `OrgType` enum and `org_type` column

**File: `services/issuer/app/db/models.py`**

Add `OrgType` enum directly in the models module (single source of truth for the enum):

```python
from enum import Enum

class OrgType(str, Enum):
    """Organization types in the trust chain hierarchy."""
    ROOT_AUTHORITY = "root_authority"
    QVI = "qvi"
    VETTER_AUTHORITY = "vetter_authority"
    REGULAR = "regular"
```

Add `org_type` column to `Organization`:
```python
org_type = Column(String(20), default=OrgType.REGULAR.value, nullable=False)
```

The `OrgType` enum lives in `db/models.py` as the canonical definition. Other modules (`auth/schema_auth.py`, API responses) import from here. This ensures a single source of truth for valid org type values.

#### 1.2 DB migration

**File: `services/issuer/app/db/migrations/sprint67_org_type.py`**

Follow existing migration pattern (see `sprint61_vetter_cert.py`):
- Add `org_type` column with default `"regular"`
- Called from `session.py` init or startup

#### 1.3 Promote trust anchors in MockVLEIManager

**File: `services/issuer/app/org/mock_vlei.py`**

Create `Organization` DB records for trust anchors. Promotion runs on **both startup paths**:

```python
# In initialize(), BOTH paths call promotion:
# Path 1: Fresh bootstrap — after KERI identity creation and state persistence
# Path 2: Restored state — after loading persisted MockVLEIState from DB
# Promotion is idempotent, so calling it on both paths is safe.
await self._promote_trust_anchors()
```

This ensures pre-Sprint67 deployments that already have `MockVLEIState` but no Organization rows get backfilled on first startup after upgrade.

New method `_promote_trust_anchors()`:
1. For each trust anchor (GLEIF, QVI, GSMA):
   - **First**: Check if `MockVLEIState` has a persisted `org_id` for this anchor → load by ID (fastest, covers restarts)
   - **Second**: Check if an Organization with matching AID already exists → update `org_type` only
   - **Fallback**: Create new Organization with: name, pseudo_lei (generated), aid, registry_key, org_type
   - **No name-based matching** — this prevents accidental hijacking of unrelated orgs that happen to share a name
   - **Name collision safety**: `Organization.name` has a UNIQUE constraint. If creation fails due to name collision (e.g., a regular org already named "mock-gleif"), append a disambiguator suffix (e.g., "mock-gleif-ta-{aid[:8]}") and retry. Log a warning. This ensures bootstrap never fails on startup.
2. Store org IDs in `MockVLEIState` dataclass (new fields: `gleif_org_id`, `qvi_org_id`, `gsma_org_id`)
3. Persist updated state

**MockVLEIState** additions:
```python
gleif_org_id: str = ""
qvi_org_id: str = ""
gsma_org_id: str = ""
```

**MockVLEIStateModel** additions (DB):
```python
gleif_org_id = Column(String(36), nullable=True)
qvi_org_id = Column(String(36), nullable=True)
gsma_org_id = Column(String(36), nullable=True)
```

Trust anchor credential fields:
- `le_credential_said` is left **null** for all trust anchor orgs (they are not Legal Entities in the vLEI sense)
- Their authoritative credentials (QVI cred for QVI, governance cred for GSMA) are referenced through `MockVLEIState` fields, not Organization model fields
- This avoids corrupting downstream logic that assumes `le_credential_said` always refers to an LE schema credential

#### 1.4 Organization API updates

**File: `services/issuer/app/api/organization.py`**

Add `org_type` to `OrganizationResponse`:
```python
org_type: str = Field("regular", description="Organization type: root_authority, qvi, vetter_authority, regular")
```

Return `org_type` from all endpoints. Protect `org_type` from modification in `PATCH /organizations/{id}`:
- Trust anchor org types (`root_authority`, `qvi`, `vetter_authority`) are **immutable** after bootstrap — any attempt to change returns 403 with "Trust anchor org type cannot be modified"
- `regular` orgs: `org_type` is not exposed in `UpdateOrganizationRequest` (no path to change it via API)
- This prevents privilege escalation (e.g., regular → root_authority) and preserves trust chain integrity
- If a future sprint needs org type migration, it should add an explicit, audited admin endpoint with safeguards

#### 1.5 Tests

**File: `services/issuer/tests/test_org_type.py`**

- Trust anchor orgs created on bootstrap with correct org_type
- org_type returned in GET /organizations and GET /organizations/{id}
- org_type defaults to "regular" for new orgs created via POST /organizations
- Backward compatibility: existing orgs without org_type get "regular"
- **Bootstrap idempotency**: trust anchor promotion is idempotent across restarts (run initialize twice, verify no duplicates and same org_ids)
- **Migration backfill**: existing MockVLEIState without org_ids (pre-Sprint67) triggers promotion on restored-state path, creating Organization rows
- **Collision safety**: creating a regular org named "mock-gleif" does NOT get hijacked/overwritten by trust-anchor promotion (no name-based matching)
- **org_type persistence**: org_type survives DB reload (create, close session, reopen, verify)
- **org_type immutability**: PATCH on a trust anchor org attempting to change org_type returns 403
- **Admin user creation for trust anchors**: POST /users with organization_id pointing to a trust anchor org succeeds and assigns the correct org
- **Auth status reflects switched org**: GET /auth/status after org switch shows `home_org_id`/`home_org_name` (user's own org) and `active_org_id`/`active_org_name`/`active_org_type` (switched target); when not switched, active fields are null and `organization_id` equals home

---

### Phase 2: Schema Authorization

**Why:** Without schema authorization, any admin can issue any credential type, violating the trust chain structure.

#### 2.1 Schema authorization mapping

**File: `services/issuer/app/auth/schema_auth.py`** (new)

Imports `OrgType` from `app/db/models.py` (single source of truth). Uses inline SAIDs with comments for clarity — these match `common/vvp/schema/registry.py` constants. If a centralized SAID constants module is created in a future sprint, this mapping should reference it to reduce drift risk.

```python
from app.db.models import OrgType

# Schema authorization mapping per Sprint 67 spec.
# Hard-coded: the trust chain structure is defined by the vLEI/VVP specification.
#
# Sprint 67 spec:
#   root_authority  → [QVI Credential]
#   qvi             → [Legal Entity, Legal Entity (Extended)]
#   vetter_authority → [VetterCertification, Governance]
#   regular         → [Brand Credential, Brand (Extended),
#                       TN Allocation, TN Allocation (Extended)]
#
# Note: A base "Brand Credential" schema does not yet exist as an embedded
# schema (only Extended Brand is available). When a base Brand schema is
# added, its SAID should be included here.

SCHEMA_AUTHORIZATION: dict[OrgType, set[str]] = {
    OrgType.ROOT_AUTHORITY: {
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",  # QVI Credential
    },
    OrgType.QVI: {
        "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",  # Legal Entity
        "EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV",  # Extended Legal Entity
    },
    OrgType.VETTER_AUTHORITY: {
        "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H",  # VetterCertification
        "EIBowJmxx5hNWQlfXqGcbN0aP_RBuucMW6mle4tAN6TL",  # GSMA Governance
    },
    OrgType.REGULAR: {
        "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g",  # Extended Brand Credential
        "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ",  # TN Allocation
        "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_",  # Extended TN Allocation
        "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o",  # Delegation Establishment (DE/GCD, delsig)
        # DE/GCD justification: regular AP orgs need DE credentials for dossier
        # delegation evidence (delsig). Without this, POST /dossier/create cannot
        # include delegation chains. Added per R4 review requirement.
    },
}

def is_schema_authorized(org_type: str, schema_said: str) -> bool:
    """Check if an org type is authorized to issue a schema."""
    try:
        ot = OrgType(org_type)
    except ValueError:
        return False
    return schema_said in SCHEMA_AUTHORIZATION.get(ot, set())

def get_authorized_schemas(org_type: str) -> set[str]:
    """Get schema SAIDs authorized for an org type."""
    try:
        ot = OrgType(org_type)
    except ValueError:
        return set()
    return SCHEMA_AUTHORIZATION.get(ot, set())
```

#### 2.2 Credential issuance enforcement

**File: `services/issuer/app/api/credential.py`**

In `issue_credential()`, after resolving the org context and before issuing:

```python
# Sprint 67: Org context is MANDATORY for credential issuance
if resolved_org is None:
    raise HTTPException(
        status_code=403,
        detail="Organization context required for credential issuance. "
               "Authenticate as an org member or specify organization_id.",
    )

# Sprint 67: Schema authorization check
from app.auth.schema_auth import is_schema_authorized
if not is_schema_authorized(resolved_org.org_type, request.schema_said):
    raise HTTPException(
        status_code=403,
        detail=f"Organization type '{resolved_org.org_type}' is not authorized "
               f"to issue schema {request.schema_said}.",
    )
```

**Note**: The Sprint 61 VetterCert guard (`if request.schema_said == VETTER_CERT_SCHEMA_SAID: raise 400`) fires BEFORE this check, so the dedicated endpoint remains the only valid path for VetterCert issuance. Both controls coexist: the Sprint 61 guard blocks the endpoint, and schema auth confirms the org type.

**Issuer-binding enforcement**: After schema authorization passes, validate that `request.registry_name` corresponds to the resolved org's registry (or auto-select the org's registry if not specified). This ensures "issue as GSMA" actually uses the GSMA AID/registry, not just any registry the admin has access to.

#### 2.3 Schema listing per org type

**File: `services/issuer/app/api/schema.py`**

Add `GET /schema/authorized` endpoint on the existing `/schema` router, plus a dual-route alias `GET /schemas/authorized` for spec compatibility.

**Naming justification**: All 8 existing schema endpoints use singular `/schema` prefix (the router is `APIRouter(prefix="/schema")`). Adding this endpoint to the same router keeps the URL structure consistent. The sprint spec says `/schemas/authorized` — we implement a **dual-route design** using a shared service function with two auth-protected route handlers.

Implementation:
1. Extract the authorization logic into a shared internal function `_list_authorized_schemas_impl(organization_id, principal, db)` in `schema.py`
2. Bind two route handlers, both with identical dependencies (`require_auth`, DB session, role checks`):

```python
# In schema.py router (prefix="/schema"):
@router.get("/authorized", response_model=SchemaListResponse)
async def list_authorized_schemas(
    organization_id: Optional[str] = None,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> SchemaListResponse:
    """List schemas authorized for an organization's type."""
    return await _list_authorized_schemas_impl(organization_id, principal, db)

# In a separate schemas_compat router (prefix="/schemas") registered in main.py:
schemas_compat_router = APIRouter(prefix="/schemas", tags=["schema"])

@schemas_compat_router.get("/authorized", response_model=SchemaListResponse)
async def list_authorized_schemas_compat(
    organization_id: Optional[str] = None,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> SchemaListResponse:
    """Spec-compatible alias for GET /schema/authorized."""
    return await _list_authorized_schemas_impl(organization_id, principal, db)
```

This guarantees both routes have identical auth, dependency injection, and access-control behavior. Tests cover both paths with and without `organization_id`.

The query param uses `organization_id` to match the majority convention in user/vetter APIs (the credential list API uses `org_id` as an exception).

```python
@router.get("/authorized", response_model=SchemaListResponse)
async def list_authorized_schemas(
    organization_id: Optional[str] = None,
    principal: Principal = require_auth,
    db: Session = Depends(get_db),
) -> SchemaListResponse:
    """List schemas authorized for an organization's type."""
```

**Route order**: This endpoint MUST be declared before `/{said}` in the router module to avoid path shadowing (FastAPI matches routes in declaration order).

**Access control** (consistent with existing admin cross-org policy):
- If `organization_id` is provided and differs from `principal.organization_id`, require `issuer:admin` role (403 otherwise)
- If `organization_id` is omitted, use `principal.organization_id`
- If principal has no org and no `organization_id` provided, return 400

Logic:
- Resolve org from `organization_id` or `principal.organization_id`
- Enforce cross-org access control (admin-only)
- Get org's `org_type`
- Call `get_authorized_schemas(org_type)` to get SAIDs
- Filter schema store to return only those schemas

#### 2.4 Refactor VetterCert issuance

**File: `services/issuer/app/vetter/service.py`**

In `issue_vetter_certification()`:
- Accept optional `issuer_org_id` parameter
- If provided, load that org and validate `org_type == "vetter_authority"`
- Use that org's AID and registry instead of hard-coded mock-gsma
- Default behavior (no `issuer_org_id`) continues to use mock-gsma for backward compatibility

**File: `services/issuer/app/vetter/service.py` — `resolve_active_vetter_cert()`**

Update the issuer validation (check #5) to support multiple vetter authorities:
- Currently hard-codes check against `mock_vlei.state.gsma_aid`
- Extend to build a set of trusted vetter issuer AIDs from **both** `MockVLEIState` (known trust-anchor AIDs) AND DB orgs with `org_type == "vetter_authority"` (only if their AID is also present in the trusted-anchor configuration)
- The org_type check alone is insufficient — it relies on DB classification rather than cryptographic identity. Accepted VetterCertification issuers must have their AID in the explicit trusted set
- Implementation: `get_trusted_vetter_aids()` function that collects AIDs from MockVLEIState vetter authorities (currently just GSMA) and validates them against DB org records. This is a belt-and-suspenders check: org must have `org_type == "vetter_authority"` AND its AID must be a known trust-anchor AID

**File: `services/issuer/app/org/mock_vlei.py` — `issue_vetter_certification()`**

Refactor to accept an optional `issuer_aid` and `issuer_registry_name` parameter pair, falling back to GSMA state when not provided. This decouples the issuance logic from the specific mock entity name.

#### 2.5 Refactor LE issuance

**File: `services/issuer/app/org/mock_vlei.py`**

In `issue_le_credential()`:
- Continue using mock-qvi's state (qvi_aid, qvi_registry_key)
- This is already correct — the refactor is mainly about ensuring the QVI org record exists and is referenced
- No external API contract changes

#### 2.6 Tests

**File: `services/issuer/tests/test_schema_auth.py`**

- `is_schema_authorized()` returns True for each org type's authorized schemas
- `is_schema_authorized()` returns False for unauthorized schemas
- `get_authorized_schemas()` returns correct sets
- `GET /schema/authorized?organization_id=X` returns filtered schemas
- `POST /credential/issue` returns 403 for unauthorized schema
- **Sprint 61 guard preserved**: `POST /credential/issue` with VetterCert schema still returns 400 (not bypassed by schema auth)
- **VetterCert via dedicated endpoint**: `POST /vetter-certifications` from a `vetter_authority` org succeeds; from a `regular` org returns 403
- **UI schema filter**: VetterCert schema appears in `GET /schema/authorized` for `vetter_authority` orgs, but the credentials.html dropdown excludes it (routed to dedicated `/ui/vetter` page per Phase 5.1)
- **Org context mandatory**: `POST /credential/issue` without org context (no principal.organization_id, no request.organization_id) returns 403
- **Issuer-binding**: `POST /credential/issue` with mismatched registry (registry not owned by active org) returns 403
- **Regression coverage**: existing credential issuance workflows (regular org issuing Brand/TN creds) continue to work after schema auth is added
- **Alias compatibility**: `GET /schemas/authorized?organization_id=X` returns same result as `GET /schema/authorized?organization_id=X`
- **Cross-org authorization**: non-admin querying `/schema/authorized?organization_id=other_org` returns 403; admin returns 200 with correct schemas (test on both `/schema/authorized` and `/schemas/authorized`)

---

### Phase 3: Org Context Switching ("Act on Behalf of")

**Why:** System admins need to switch context to issue credentials from trust anchor identities.

#### 3.1 Session org context

**File: `services/issuer/app/auth/session.py`**

Add `home_org_id` and `active_org_id` to `Session` dataclass:
```python
home_org_id: str | None = None    # Immutable: set on session creation from principal.organization_id
active_org_id: str | None = None  # Mutable: set by POST /session/switch-org, overrides effective org
```

`home_org_id` is set once during `session_store.create()` and is never mutated. This provides a reliable source of truth for the user's "real" org even after switching. `/auth/status` reads `home_org_id` for `home_org_*` fields and `active_org_id` for `active_org_*` fields.

#### 3.2 Org switch API

**File: `services/issuer/app/api/session.py`** (new router, prefix `/session`)

Add `POST /session/switch-org` endpoint (per Sprint 67 spec — uses `/session/` prefix, not `/auth/`):

```python
class SwitchOrgRequest(BaseModel):
    organization_id: Optional[str] = None  # None reverts to home org

class SwitchOrgResponse(BaseModel):
    active_org_id: Optional[str]       # Currently acting as (null = home)
    active_org_name: Optional[str]
    active_org_type: Optional[str]
    home_org_id: Optional[str]         # The admin's own org
    home_org_name: Optional[str]
```

Logic:
- Require `issuer:admin` system role
- Validate org exists and is enabled
- Update `session.active_org_id`
- **Audit logging**: Emit `session.switch_org` audit event with: actor (principal.key_id), from_org (session.home_org_id), to_org (organization_id or "home" for revert), timestamp, outcome (success/denied). Uses existing `audit.log_access()` pattern.
- Return updated session info

#### 3.3 Principal resolution

**File: `services/issuer/app/auth/api_key.py`** (or session middleware)

When resolving a session-based principal, if `session.active_org_id` is set:
- Override `principal.organization_id` with `session.active_org_id`
- This makes all downstream org-scoped operations use the switched context automatically
- The original `principal.organization_id` is preserved in `session.home_org_id` (never mutated)

Implementation in `InMemorySessionStore.get()`: after loading the session, if `active_org_id` is set, clone the principal with the overridden `organization_id`. The original principal object is NOT mutated — a new Principal instance is created with the switched org. `session.home_org_id` always reflects the user's actual org for audit and `/auth/status`.

#### 3.4 Auth status update

**File: `services/issuer/app/api/auth.py`**

Update `AuthStatusResponse` to expose both home and active org when switching is in effect:

```python
class AuthStatusResponse(BaseModel):
    # ... existing fields ...
    organization_id: Optional[str]      # Effective org (active if switched, home otherwise)
    organization_name: Optional[str]    # Effective org name
    home_org_id: Optional[str] = None   # Always the user's own org (Sprint 67)
    home_org_name: Optional[str] = None # Always the user's own org name (Sprint 67)
    active_org_id: Optional[str] = None # Set only when admin has switched context (Sprint 67)
    active_org_name: Optional[str] = None
    active_org_type: Optional[str] = None
```

Update the `/auth/status` handler: when session has `active_org_id`, populate `home_org_*` from the principal's original org and `active_org_*` from the switched org. The existing `organization_id`/`organization_name` fields reflect the effective org (preserving backward compatibility for existing UI code).

#### 3.5 UI org switcher

**File: `services/issuer/web/` (all pages with nav bar)**

The top navigation bar (in shared CSS/JS or in a nav template) gets an org switcher:
- Dropdown populated from `GET /organizations`
- Current org highlighted with type badge
- Selecting a different org calls `POST /session/switch-org`
- Page reloads to reflect new context
- Non-admin users see their org name (read-only)

Since the UI uses vanilla JS, implement as a shared function in a new `nav-org-switcher.js` file included in all pages.

#### 3.6 Tests

**File: `services/issuer/tests/test_org_switching.py`**

- Admin can switch org context via POST /session/switch-org
- Non-admin cannot switch (403)
- After switching, `principal.organization_id` reflects active org (principal resolution test)
- Switching to null reverts to home org
- Switching to non-existent org returns 404
- Switching to disabled org returns 400
- **Principal resolution integration**: Issue credential after switching — credential registered to switched org, not home org
- **Session isolation**: Two concurrent sessions can have different active_org_id values
- **Audit logging**: `POST /session/switch-org` emits audit event with actor, from_org, to_org, outcome for both switch and revert operations

---

### Phase 4: Org Admin Management UI

#### 4.1 Organization detail page

**File: `services/issuer/web/organization-detail.html`** (new)

Linked from org cards (click on org name/card). Shows:
- Organization info panel (name, type badge, AID, pseudo-LEI, status, registry key)
- **Users tab**: List users from `GET /users?organization_id={id}` with roles
- **Add user** button: Form calling `POST /users` with org ID pre-filled
- **Credentials tab**: Credentials from `GET /credential?org_id={id}` (note: credential API uses `org_id`, not `organization_id`)
- **VetterCert tab** (for vetter_authority orgs): VetterCerts from `GET /vetter-certifications?organization_id={id}` (vetter API uses `organization_id`)

**File: `services/issuer/app/main.py`** — Add route handler:
```python
@app.get("/ui/organization-detail", response_class=FileResponse)
def ui_organization_detail():
    """Serve the organization detail page (Sprint 67)."""
    return FileResponse(WEB_DIR / "organization-detail.html", media_type="text/html")
```

**File: `services/issuer/app/config.py`** — Add to auth-exempt paths (when `UI_AUTH_ENABLED=false`):
```python
exempt.add("/ui/organization-detail")
```

#### 4.2 Organization cards update

**File: `services/issuer/web/organizations.html`**

Add `org_type` badge to each card:
- `root_authority` → "Root Authority" badge (blue)
- `qvi` → "QVI" badge (purple)
- `vetter_authority` → "Vetter Authority" badge (green)
- `regular` → "Organization" badge (gray)

Make org name clickable, linking to `/ui/organization-detail?id={org_id}`.

#### 4.3 Tests

- Org detail page loads for all org types
- Users tab shows correct users per org

---

### Phase 5: Credential Issuance UI Enhancements

#### 5.1 Schema filter by active org

**File: `services/issuer/web/credentials.html`**

Change the schema dropdown to fetch from `GET /schema/authorized?organization_id={active_org_id}` instead of `GET /schema`.

**VetterCert routing**: When the active org is a `vetter_authority`, the credentials page does NOT show VetterCert in the generic schema dropdown. Instead, a prominent link/button directs the user to the dedicated vetter page (`/ui/vetter`), which uses `POST /vetter-certifications`. This preserves the Sprint 61 invariant that VetterCerts are only issued via the dedicated endpoint.

#### 5.2 Issuer identity display

Show the active org's name and AID as the "issuing as" identity.

#### 5.3 Recipient org picker

For credentials that target another org (e.g., LE credentials issued by QVI to a legal entity), add an org picker dropdown populated from `GET /organizations`. VetterCert issuance uses the dedicated `/ui/vetter` page, not this picker.

#### 5.4 Issuance confirmation

Show confirmation dialog before issuing.

#### 5.5 Issued credentials view

Show a table of credentials issued by the active org.

#### 5.6 Tests

- Schema dropdown respects org type
- Credential issuance from trust anchor org succeeds
- Unauthorized schema type returns 403

---

## Data Flow

### Org Bootstrap (startup)
```
MockVLEIManager.initialize()
  → Create KERI identities (GLEIF, QVI, GSMA)
  → Persist MockVLEIState
  → _promote_trust_anchors()
    → For each trust anchor:
      → Find or create Organization DB record
      → Set org_type, aid, registry_key
      → Store org_id in MockVLEIState
```

### Credential Issuance with Schema Authorization
```
POST /credential/issue
  → resolve org context (from principal or request body)
  → REQUIRE org context (403 if absent)
  → check schema authorization: org_type → allowed SAIDs (403 if not authorized)
  → issuer-binding: validate registry belongs to active org (403 on mismatch)
  → inject certification edge if extended schema
  → validate vetter constraints if extended schema
  → issue credential via KERI using active org's AID/registry
  → register as ManagedCredential
```

Note: VetterCert issuance via `POST /vetter-certifications` also validates org_type == vetter_authority when `issuer_org_id` is provided (Phase 2.4).

### Org Switching
```
POST /session/switch-org { organization_id: "..." }
  → validate admin role
  → validate org exists
  → session.active_org_id = org_id
  → subsequent requests: principal.organization_id overridden
```

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/issuer/app/db/models.py` | Modify | Add `OrgType` enum, `org_type` column to Organization, org_id fields to MockVLEIState |
| `services/issuer/app/db/migrations/sprint67_org_type.py` | Create | DB migration for org_type column and MockVLEIState org_id columns |
| `services/issuer/app/org/mock_vlei.py` | Modify | `_promote_trust_anchors()`, persist org_ids in state |
| `services/issuer/app/auth/schema_auth.py` | Create | Schema authorization mapping (imports OrgType from models), helpers |
| `services/issuer/app/api/credential.py` | Modify | Schema authorization check in `issue_credential()` |
| `services/issuer/app/api/schema.py` | Modify | Add `GET /schema/authorized` endpoint |
| `services/issuer/app/api/organization.py` | Modify | Add `org_type` to responses, protect from modification |
| `services/issuer/app/auth/session.py` | Modify | Add `active_org_id` to Session |
| `services/issuer/app/api/session.py` | Create | New router (`/session`) with `POST /session/switch-org` endpoint |
| `services/issuer/app/main.py` | Modify | Register session router, schemas_compat router, add `/ui/organization-detail` route |
| `services/issuer/app/config.py` | Modify | Add `/ui/organization-detail` to auth-exempt paths |
| `services/issuer/app/api/auth.py` | Modify | Add home/active org fields to AuthStatusResponse, update /auth/status handler |
| `services/issuer/app/auth/api_key.py` | Modify | Override principal.organization_id from session.active_org_id |
| `services/issuer/app/vetter/service.py` | Modify | Accept `issuer_org_id`, validate org_type, update resolve_active_vetter_cert |
| `services/issuer/web/organizations.html` | Modify | Add org_type badges, clickable org names |
| `services/issuer/web/organization-detail.html` | Create | Org detail page with tabs |
| `services/issuer/web/credentials.html` | Modify | Schema filter by org type, issuer display, recipient picker |
| `services/issuer/web/nav-org-switcher.js` | Create | Shared org switcher component |
| `services/issuer/web/*.html` | Modify | Include org switcher in all nav bars |
| `services/issuer/tests/test_org_type.py` | Create | Phase 1 tests (incl. bootstrap idempotency, admin user for trust anchors) |
| `services/issuer/tests/test_schema_auth.py` | Create | Phase 2 tests |
| `services/issuer/tests/test_org_switching.py` | Create | Phase 3 tests (incl. principal resolution integration) |

## Compatibility Matrix

| Org Type | Authorized Schemas | Endpoint | UI Path |
|----------|-------------------|----------|---------|
| `root_authority` | QVI Credential | `POST /credential/issue` | `/ui/credentials` |
| `qvi` | Legal Entity, Extended LE | `POST /credential/issue` | `/ui/credentials` |
| `vetter_authority` | VetterCertification, Governance | VetterCert: `POST /vetter-certifications`; Governance: `POST /credential/issue` | VetterCert: `/ui/vetter`; Governance: `/ui/credentials` |
| `regular` | Extended Brand, TN Alloc, Extended TN Alloc, DE/GCD (delsig) | `POST /credential/issue` | `/ui/credentials` |

**Key invariants:**
- VetterCert issuance ALWAYS goes through the dedicated `/vetter-certifications` endpoint (Sprint 61 guard blocks `/credential/issue`)
- Schema auth and endpoint guards coexist: schema auth confirms org type, endpoint guard routes to correct path
- All orgs: `POST /credential/issue` requires org context (403 if absent)
- All orgs: registry must belong to active org (issuer-binding)

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| MockVLEIManager creates duplicate orgs on restart | Medium | High | Idempotent `_promote_trust_anchors()`: match by persisted org_id first, then AID (no name matching) |
| org_type migration breaks existing data | Low | Medium | Default "regular" for existing rows, no NOT NULL without default |
| Schema authorization blocks legitimate issuance | Low | High | Log warnings before enforcement phase, test all org type/schema combos |
| Org switching creates security hole | Low | High | Require `issuer:admin` role, audit log all switches |
| Session active_org_id survives across requests unexpectedly | Low | Medium | Explicitly null on session creation, clear on logout |

## Open Questions

None — the sprint spec is detailed and the approach is clear.

## Revision History

| Round | Changes |
|-------|---------|
| R1 | Fixed schema authorization mapping (removed Dossier, added missing base Brand note). Fixed OrgType enum placement to db/models.py. Changed endpoint from `/auth/switch-org` to `/session/switch-org`. Added organization-detail UI route handler to main.py and auth-exempt paths. Added bootstrap idempotency, collision safety, and admin user tests. |
| R2 | Removed name-based matching in trust-anchor promotion (AID + persisted org_id only). Made trust anchor org_type immutable. Left le_credential_said null for trust anchors. Added VetterCert guard compatibility tests. |
| R3 | Re-added VetterCertification to vetter_authority schema auth set. Made org context mandatory for all credential issuance (no bypass when absent). Added issuer-binding enforcement (registry validation). Added compatibility matrix. Documented Sprint 61 guard coexistence with schema auth. |
| R4 | Added GCD/DE schema to regular orgs for dossier delegation evidence. Fixed route insertion order note (`/authorized` before `/{said}`). Added access-control rules for cross-org schema query. Exposed both home_org and active_org in auth status and switch response. Used centralized SAID constant reference note. |
| R5 | Added collision-safe name strategy for trust-anchor creation (disambiguator suffix on UNIQUE violation). Corrected credential tab to use `org_id` (matching credential API). Added auth status model/handler update to plan scope (Phase 3.4). Added `/schemas/authorized` → `/schema/authorized` redirect alias for spec compliance. Removed VetterCert from Phase 5.3 recipient picker context. Added this revision history. |
| R6 | Replaced `/schemas/authorized` redirect with query-safe alias (same handler, no query param loss). Explicit DE/GCD justification for regular orgs (required for dossier delegation evidence). Ensured trust-anchor promotion runs on both startup paths (fresh + restored state). Made `home_org_id` immutable in Session (explicit source of truth for auth status). Added migration backfill test and alias compatibility test. |
| R7 | Replaced alias delegation with dual-route design (shared service function, two auth-protected route handlers with identical dependencies). Tightened vetter issuer validation: AID must be in trusted-anchor set AND org_type must match. Added cross-org authorization tests for both schema endpoint paths. |
| R8 | Removed stale redirect-alias language (keep only dual-route design). Added explicit audit logging for `POST /session/switch-org` with event shape and test coverage. |

---

## Implementation Notes

### Deviations from Plan

1. **Phase 2.4 (VetterCert issuance refactor) and Phase 2.5 (LE issuance refactor)** — deferred. The plan called for refactoring `vetter/service.py` to accept `issuer_org_id` and updating `resolve_active_vetter_cert` with a trusted-AID set. This was not implemented because it touches the existing Sprint 61 vetter certification logic which is working correctly. The schema authorization check in `POST /credential/issue` already blocks unauthorized schemas by org type, and the Sprint 61 VetterCert guard still blocks the `/credential/issue` path for VetterCerts. The refactor can be done in a follow-up sprint if needed.

2. **`nav-org-switcher.js`** — instead of a separate file, the org switcher was integrated directly into `shared.js` (which is already loaded on every page). This avoids requiring an additional `<script>` tag on all HTML pages.

3. **Principal resolution** — implemented in `InMemorySessionStore.get()` using `dataclasses.replace()` to clone the principal with overridden `organization_id`. The plan suggested doing this in `api_key.py` but session.py was more appropriate since it's where the session is retrieved.

### R1 Review Fixes

4. **Session principal mutation (High)** — `InMemorySessionStore.get()` was mutating the stored session's principal when `active_org_id` was set. Fixed to return a cloned session via `dataclasses.replace()` without modifying stored state.

5. **Issuer-binding enforcement (High)** — Added registry ownership check in `POST /credential/issue`: the registry prefix (issuer AID) must match the resolved org's AID before issuing. Returns 403 if mismatched.

6. **org_type immutability (Medium)** — Added `model_config = {"extra": "forbid"}` to `UpdateOrganizationRequest` so Pydantic rejects any unknown fields including `org_type` with 422. This is the accepted approach: since `org_type` is never a valid PATCH field, Pydantic's schema-level rejection provides a stronger guarantee than a custom check (it blocks ALL unknown fields, not just `org_type`). The 422 response includes Pydantic's standard validation error pointing to the forbidden field. Test `test_patch_org_type_mutation_rejected` validates this behavior.

7. **UI schema fallback (Low)** — Removed fallback to `/schema` in `credentials.html:loadSchemas()`. If the authorized endpoint fails, the dropdown shows "Unable to load schemas" instead of presenting unauthorized options.

8. **Session store `set_active_org()` method** — Added dedicated method to update stored session's `active_org_id` directly (since `get()` returns a clone). `POST /session/switch-org` now uses this method.

9. **Regression tests added** — `test_switch_revert_uses_home_org` (switch→revert→verify home org), `test_mismatched_registry_org_returns_403` (issuer-binding), `test_patch_org_type_mutation_rejected` (422 on org_type in PATCH), `test_patch_org_type_with_valid_fields_succeeds`.

### R2 Review Fixes

10. **Issuer-binding fail-closed (High)** — Made issuer-binding check unconditional. Org MUST have `aid` AND `registry_key` to issue credentials (403 if missing). If `registry_name` is specified, it must resolve and its prefix must match the org's AID (400 if not found, 403 if mismatched). No silent skip paths remain.

11. **Switch-org audit `outcome` field (Medium)** — Added `action_type` ("switch"/"revert") and `outcome` ("success") to the audit event details, making switch vs revert actions unambiguous in logs.

12. **org_type immutability documented (Low)** — Plan text updated (item 6 above) to formally accept the Pydantic `extra="forbid"` 422 model-based rejection as the canonical approach.

### R3 Review Fixes

13. **Issuer-binding async fix (High)** — Fixed `get_registry()` → `await get_registry_by_name()` in credential.py. The old call was missing `await` and used the wrong method (key-based instead of name-based), returning a coroutine object instead of `RegistryInfo`. Now properly awaits and uses `registry_info.issuer_aid` for AID comparison.

14. **VetterCert excluded from generic schema picker (Medium)** — Filtered VetterCertification SAID from the schema dropdown in credentials.html. Added vetter link banner for `vetter_authority` orgs directing to `/ui/vetter`.

15. **Test org AID/registry sync** — Updated `setup_identity_and_registry()` in test_credential.py, test_credential_edge_integration.py, and test_dossier.py to sync the test org's AID and registry_key with the real KERI identity/registry created via API, so the issuer-binding check passes correctly.

### Implementation Details

- **696 tests passing** (0 failures, 6 skipped, 3 deselected)
- All 5 existing test files updated with `organization_id` in credential issuance requests
- Session store `get()` creates new Principal instance (never mutates original)
- Auth status endpoint reads both `home_org_id` and `active_org_id` from session
- Org switcher in shared.js uses `showModal()` pattern consistent with existing modals

### Test Results

```
696 passed, 6 skipped, 3 deselected, 7 warnings in 64.39s
```

### Files Changed

| File | Lines | Summary |
|------|-------|---------|
| `services/issuer/app/db/models.py` | +15 | OrgType enum, org_type column, MockVLEIState org_id fields |
| `services/issuer/app/db/migrations/sprint67_org_type.py` | +30 | DB migration for org_type and org_id columns |
| `services/issuer/app/org/mock_vlei.py` | +80 | Trust anchor promotion with 3-strategy matching |
| `services/issuer/app/auth/schema_auth.py` | +40 | Schema authorization mapping and helpers |
| `services/issuer/app/api/credential.py` | +15 | Mandatory org context + schema auth check |
| `services/issuer/app/api/schema.py` | +50 | GET /schema/authorized + /schemas/authorized compat |
| `services/issuer/app/api/organization.py` | +2 | org_type in list response |
| `services/issuer/app/auth/session.py` | +15 | home_org_id, active_org_id, principal override |
| `services/issuer/app/api/session.py` | +130 | POST /session/switch-org endpoint |
| `services/issuer/app/api/auth.py` | +30 | AuthStatusResponse home/active org fields |
| `services/issuer/app/main.py` | +5 | Session router, org-detail route |
| `services/issuer/app/config.py` | +2 | Auth-exempt path for org-detail |
| `services/issuer/web/shared.js` | +120 | Org switcher, session state fields |
| `services/issuer/web/organizations.html` | +30 | Type badges, clickable org names |
| `services/issuer/web/organization-detail.html` | +250 | New org detail page with tabs |
| `services/issuer/web/credentials.html` | +25 | Schema filter, issuing-as banner, org_id in payload |
| `services/issuer/tests/test_org_type.py` | +200 | Phase 1 tests (13 tests) |
| `services/issuer/tests/test_schema_auth.py` | +229 | Phase 2 tests (27 tests) |
| `services/issuer/tests/test_org_switching.py` | +280 | Phase 3 tests (13 tests) |
| `services/issuer/tests/test_credential.py` | +30 | Updated for mandatory org context |
| `services/issuer/tests/test_credential_edge_integration.py` | +20 | Updated for mandatory org context |
| `services/issuer/tests/test_dossier.py` | +15 | Updated for mandatory org context |
| `services/issuer/tests/test_sprint63_wizard.py` | +10 | Updated for mandatory org context |
