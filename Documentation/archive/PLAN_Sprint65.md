# Sprint 65: Schema-Aware Credential Management

## Problem Statement

The credential creation page (`credentials.html`) has a dynamic form generator for attributes (`SchemaFormGenerator`) but edge management is entirely manual — users must know edge names, target credential SAIDs, schema SAIDs, and operators by heart. Meanwhile, every schema JSON file already defines its edge requirements. This sprint surfaces schema-defined edge information in the UI so credential creation becomes guided rather than requiring deep ACDC expertise.

## Spec References

- **VVP Spec §6.3 — Dossier Credential Chain**: Dossier assembles backing credentials via edges with specific schema-defined attributes and edge requirements.
- **ACDC Spec — Edges Block**: The `e` property of each schema JSON defines required/optional edges with `n` (SAID), `s` (schema constraint), and `o` (operator: `I2I`/`NI2I`).
- **VVP Spec §6.3.6 — TN Allocation**: TNAlloc credentials require specific attributes and may chain to an issuer identity credential.

## Current State

**What exists:**
- `SchemaFormGenerator` class in `credentials.html` (lines 491-739) — parses `properties.a.oneOf[1]` to render dynamic attribute forms
- `FormDataCollector` class (lines 742-803) — serializes form data back to JSON
- Manual edge management (lines 376-459) — user picks from hardcoded `EDGE_TYPES` dropdown + types target SAID
- `EDGE_TYPES` array (line 377-384): `certification`, `vetting`, `delegation`, `jl`, `le`, `custom`
- `collectEdges()` function (lines 431-454) — only collects `n` and `s` (from credential lookup), no operator
- Datalist-based SAID autocomplete for edge targets (lines 930-934)
- Dossier wizard (`dossier.html`) already has hardcoded `EDGE_SLOTS` (lines 420-427) with schema constraints, but these are manually maintained
- `GET /schema/{said}` returns full `schema_document` including edge definitions
- `GET /credential?schema_said=...&org_id=...` filters credentials (Sprint 63)
- 13 embedded schema JSON files covering all VVP credential types

**What's missing:**
1. No schema-driven edge awareness — edges block is ignored by `SchemaFormGenerator`
2. No automatic edge slot rendering based on selected schema's edge requirements
3. No filtering of candidate credentials per edge slot (by schema SAID constraint)
4. No operator auto-population from schema definition
5. No required/optional distinction for edges
6. No credential type labels on edge target candidates
7. No dossier readiness view
8. Edge schema SAID (`s` field) must be manually looked up

## Proposed Solution

### Approach

Build a `SchemaEdgeParser` class that mirrors `SchemaFormGenerator` — it parses `properties.e.oneOf[1]` the same way the form generator parses `properties.a.oneOf[1]`. When a schema is selected, both attribute form fields AND edge slots are rendered automatically. Each edge slot gets a credential picker filtered by schema constraint and operator, replacing the manual edge entry.

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| Server-side edge parsing (return edge metadata from API) | Single source of truth | Requires new API, duplicates schema data already in JSON | Schema JSON already has everything needed, client-side parsing is simpler |
| Embed edge metadata in schema list response | Faster load | Changes API contract, bloats list response | Schema detail is already fetched on selection; no need to pre-load |
| Replace manual edge UI entirely | Simpler code | Breaks forward compatibility with unknown edge names | Keeping "+ Add Edge" fallback is low-cost and handles future schemas |

### Detailed Design

#### Phase 1: SchemaEdgeParser Class

**Purpose:** Parse the edges block from a schema JSON document and return structured edge slot metadata.

**Location:** `services/issuer/web/credentials.html` (inline, parallel to `SchemaFormGenerator`)

**Class Interface:**
```javascript
class SchemaEdgeParser {
    /**
     * Parse edge definitions from a schema document.
     * @param {Object} schemaDoc - Full schema JSON document
     * @returns {Array<EdgeSlot>} Array of edge slot definitions
     */
    static parseEdges(schemaDoc) { ... }
}

// EdgeSlot structure:
{
    name: string,              // Edge name (e.g., "tnalloc", "vetting")
    required: boolean,         // Whether listed in e.required[]
    schemaConstraint: string|null,  // const value from s property, or null
    operator: string|null,     // const value from o property (e.g., "I2I", "NI2I")
    description: string,       // From edge property description
    hasOperator: boolean       // Whether operator is constrained
}
```

**Parsing Logic:**

1. Extract edges block: `schemaDoc.properties?.e?.oneOf` → find the object variant by scanning for `type === "object"` (NOT by index — `oneOf[1]` is the common case but not guaranteed by spec)
   ```javascript
   const edgesOneOf = schemaDoc.properties?.e?.oneOf;
   if (!edgesOneOf) return [];
   const edgesObj = edgesOneOf.find(v => v.type === 'object');
   if (!edgesObj) return [];
   ```
2. Get `required` array from the edges object variant (filter out `"d"`)
3. For each property in `properties` (excluding `"d"`):
   - `name` = property key
   - `required` = name is in the required array
   - `schemaConstraint` = `prop.properties?.s?.const || null`
   - `operator` = `prop.properties?.o?.const || null`
   - `description` = `prop.description || ""`

**The same type-based detection must be used in the Python `parse_schema_edges()` utility:**
```python
def parse_schema_edges(schema_doc: dict) -> list[dict]:
    """Parse edge slot definitions from a schema JSON document."""
    edges_one_of = schema_doc.get("properties", {}).get("e", {}).get("oneOf")
    if not edges_one_of:
        return []
    edges_obj = next((v for v in edges_one_of if v.get("type") == "object"), None)
    if not edges_obj:
        return []
    required_edges = set(edges_obj.get("required", [])) - {"d"}
    # ... extract edge slots from edges_obj["properties"]
```

**Edge cases handled:**
- Schema with no `e` property (e.g., some simple credential types) → empty array
- Schema with `e` as string only (SAID reference, no inline) → empty array
- Edge with no `const` on `s` (unconstrained schema) → `schemaConstraint: null`
- Edge with no `const` on `o` (unconstrained operator) → `operator: null`
- `oneOf` with reversed order (string first, then object, or vice versa) → handled by type-based detection

#### Phase 2: Schema-Driven Edge UI

**Purpose:** When a schema is selected, auto-render edge slots with credential pickers filtered by schema constraint and operator.

**UI Structure per Edge Slot:**
```
┌─────────────────────────────────────────────────────┐
│ ▼ tnalloc — TN Allocation                [Required] │
├─────────────────────────────────────────────────────┤
│ Description: Chain to a TN allocation credential... │
│ Operator: I2I (auto)  │  Schema: EFvno... (auto)   │
│                                                     │
│ Select credential:                                  │
│ ┌─ ● EeRk4...ab3Q  TN Allocation  +1202555... ──┐  │
│ │  ○ EfGh7...xY2P  TN Allocation  +4420777... │  │
│ └────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**Implementation Details:**

1. **Edge section container** — Added after the dynamic form container in the credential form:
   ```html
   <div id="schemaEdgesContainer" style="display:none">
       <h4>Credential Edges (from schema)</h4>
       <div id="schemaEdgeSlots"></div>
   </div>
   ```

2. **Rendering flow** — When schema is selected (existing `schemaSelect.change` handler, line 806):
   ```javascript
   // After SchemaFormGenerator.generateFromSchema(said, dynamicFormContainer):
   const edgeSlots = SchemaEdgeParser.parseEdges(currentSchemaDoc);
   renderSchemaEdgeSlots(edgeSlots);
   ```

3. **`renderSchemaEdgeSlots(edgeSlots)`** — For each edge slot:
   - Create a collapsible card (matching dossier.html pattern: header + body)
   - Header shows: edge name (formatted), description, required/optional badge
   - Body shows: operator (read-only), schema constraint (read-only), credential picker
   - If no edge slots, hide the container

4. **`loadEdgeCandidates(slot)`** — Fetch matching credentials with org-scoped context:

   **Org context determination** (matches Sprint 63 model):
   - **Normal user flow**: `currentOrgId` from the authenticated session (`currentSession.organizationId`)
   - **Admin flow**: If admin is issuing on behalf of another org, use the org selected in a new "Issuing Organization" selector (populated from `GET /organizations/names`). This mirrors how dossier.html Step 1 selects the AP org.
   - **Deep-link flow**: If `?org={id}` query param is present (from dossier "Create" link), use that org ID and display it read-only.
   - **Fallback**: If no org context is available (unauthenticated or admin without selection), fetch all credentials without org filter.

   **Credential candidate loading on `credentials.html`:**

   The credentials page uses a simple, uniform loading rule — NO per-edge access policies:
   ```javascript
   // credentials.html — ALL edges use the same org context uniformly
   const params = new URLSearchParams();
   if (slot.schemaConstraint) params.set('schema_said', slot.schemaConstraint);
   if (edgeOrgContext) params.set('org_id', edgeOrgContext);
   const res = await authFetch(`/credential?${params}`);
   ```

   **This is NOT dossier.html.** Per-edge access policies (`ap_org` vs `principal`) are a dossier-only concept, used exclusively in `dossier.html`'s hardcoded `EDGE_SLOTS` from Sprint 63. The generic credentials page does not replicate that logic. `SchemaEdgeParser` outputs name, required, schema constraint, and operator — NOT access policies. All edge candidate loading on the credentials page uses `edgeOrgContext` uniformly for all edge slots.

   **I2I filtering** (client-side, after API response):
   - If `slot.operator === "I2I"` AND `edgeOrgContext` is set: filter results to `relationship === "subject"` (credentials issued TO the org). This is correct because the `org_id` filter already scopes results, and `relationship === "subject"` ensures the org is the issuee.
   - If `slot.operator === "I2I"` AND no `edgeOrgContext`: show an empty picker with message "Select an organization to see I2I edge candidates." The edge slot is not selectable until org context is established. This prevents semantically invalid credential selection.
   - If `slot.operator === "NI2I"` or null: show all credentials returned by the query (no relationship filtering).

   - Render as radio-button list showing: truncated SAID, schema type label, key attributes

5. **Schema type labels** — Build a `Map<SAID, title>` at page load from the existing `loadSchemas()` call:
   ```javascript
   const schemaLabelMap = new Map();
   // In loadSchemas(), after loading:
   for (const schema of data.schemas) {
       schemaLabelMap.set(schema.said, schema.title);
   }
   ```

6. **Credential attribute preview** — Show key attributes inline for each candidate:
   - TNAlloc: phone numbers from `attributes.numbers.tn` or range
   - LE/Extended LE: LEI, legal name
   - Brand: brand name
   - GCD: role, delegate AID (truncated)
   - Fetch from `GET /credential/{said}` (detail endpoint) lazily on first expand

7. **collectEdges() update** — Merge schema-driven edge selections with manual edges:
   ```javascript
   function collectEdges() {
       const edges = {};
       // Collect schema-driven edge selections
       schemaEdgeSelections.forEach((said, edgeName) => {
           if (said) {
               const slot = currentEdgeSlots.find(s => s.name === edgeName);
               const cred = availableCredentials.find(c => c.said === said);
               edges[edgeName] = {
                   n: said,
                   s: slot?.schemaConstraint || cred?.schema_said || '',
                   ...(slot?.operator ? { o: slot.operator } : {})
               };
           }
       });
       // Also collect manual edges (existing code)
       // ...merge...
       return Object.keys(edges).length > 0 ? edges : null;
   }
   ```

8. **Fallback manual edges** — The existing "+ Add Edge" button remains below the schema-driven section for custom edges not defined in the schema.

#### Phase 3: Credential Type Quick-Create Templates

**Purpose:** Provide quick-access cards for common VVP credential types above the generic schema dropdown.

**Implementation:**

1. **VVP credential type cards** — A horizontal card row above the schema dropdown:
   ```html
   <div id="credentialTypeCards" class="credential-type-cards">
       <!-- Populated dynamically from schema list -->
   </div>
   ```

   **Card generation strategy** — Derived from the loaded schema list's `title` field (available in `GET /schema` list response). A `VVP_CREDENTIAL_TYPES` allowlist maps title substrings to card metadata:
   ```javascript
   const VVP_CREDENTIAL_TYPES = [
       { match: 'TN Allocation', label: 'TN Allocation', description: 'Phone number allocation', order: 1 },
       { match: 'Cooperative Delegation', label: 'Delegated Signer', description: 'Delegation credential', order: 2 },
       { match: 'Legal Entity', label: 'Legal Entity', description: 'Organization identity', order: 3 },
       { match: 'Brand', label: 'Brand Credential', description: 'Brand ownership', order: 4 },
       { match: 'Vetter Certification', label: 'Vetter Cert', description: 'Vetter authority', order: 5 },
   ];
   ```
   Cards are rendered by matching each loaded schema's `title` (from `GET /schema` list, e.g., "TN Allocation Credential", "Generalized Cooperative Delegation Credential") against the allowlist via `title.includes(match)`. This uses data already available in the list response without API changes. Note: `GET /schema` returns `schema_document: null` in the list response (line 73 of schema.py), so `credentialType` from the schema document is NOT available. The `title` field is the reliable matching key.

   Clicking a card selects the schema in the dropdown (triggers existing change handler).

2. **"Create for Dossier" deep link support** — Read URL query params on page load:
   - `?schema={SAID}` → pre-select schema
   - `?context=dossier` → show "Return to Dossier" banner
   - `?edge={name}` → highlight the relevant edge slot
   - `?org={id}` → pre-fill recipient AID from org lookup

3. **Recipient AID helper** — For credentials requiring a recipient (`a.i`), add an org picker dropdown alongside the raw AID input:
   - Populated from `GET /organizations/names`
   - Selecting an org fills in its AID
   - Raw AID input remains for manual entry

#### Phase 4: Dossier Readiness Dashboard

**Purpose:** Show which credentials an org has vs needs for dossier assembly.

**Backend: `GET /dossier/readiness?org_id={uuid}`**

**Route convention note:** The issuer API uses unprefixed router paths. The dossier router is `APIRouter(prefix="/dossier")` (line 42 of dossier.py), so endpoints are `/dossier/create`, `/dossier/build`, etc. All UI `authFetch()` calls use these paths directly (e.g., `authFetch('/dossier/create', ...)` at dossier.html:867, `authFetch('/credential', ...)` at credentials.html:920). CHANGES.md occasionally documents these as `/api/dossier/...` as a shorthand, but the actual runtime routes are unprefixed. The new endpoint follows the canonical convention: `GET /dossier/readiness`.

**Location:** `services/issuer/app/api/dossier.py` (same router as existing `/dossier/create`, `/dossier/build`, etc.)

**Implementation:**
```python
@router.get("/readiness")
async def dossier_readiness(
    org_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Check dossier-issuable readiness for each edge slot.

    This is NOT just credential availability — it validates the same constraints
    that POST /dossier/create would enforce (from Sprint 63's _validate_dossier_edges):
    """
    # 1. Verify org exists and caller has access (same pattern as list_associated_dossiers)
    # 2. Use DOSSIER_EDGE_DEFS constant (already defined in dossier.py, lines 52-59)
    # 3. For each edge slot, find matching credentials with FULL validation:
    #    a. Filter by schema_said constraint (if any)
    #    b. Filter by org ownership (org_id)
    #    c. Exclude revoked credentials (status != 'revoked')
    #    d. I2I check: if edge.operator == "I2I", credential's recipient_aid must match org's AID
    #    e. delsig-specific: issuer must be AP (org's AID), issuee must exist
    #    f. Access policy: ap_org edges filter by org, principal edge (bproxy) filters by session
    # 4. Readiness = can a dossier be issued? The `ready` flag is true when:
    #    a. ALL REQUIRED edges (vetting, alloc, tnalloc, delsig) have >=1 valid credential
    #    b. Optional edges (bownr, bproxy) report status but do not block readiness.
    # 5. bproxy gate (§6.3.4) — NOT applied at readiness level (revised):
    #    bownr/bproxy are unconstrained optional edges (schema=None), so readiness
    #    cannot reliably detect actual brand ownership/proxy credentials among all
    #    org credentials.  The bproxy conditional gate is deferred to POST /dossier/create
    #    where the user selects specific edges and full validation is applied.
    # 6. Return readiness status per slot with detailed status:
    #    - "ready": at least one valid credential passes all checks
    #    - "missing": no credentials available for this slot (blocking if required)
    #    - "invalid": non-revoked credentials exist but none pass validation (I2I mismatch, etc.)
    #    - "optional_missing": optional slot with no credentials (not blocking)
    #    - "optional_unconstrained": optional slot with no schema constraint — candidates
    #      exist but suitability requires manual assessment (e.g., bownr/bproxy)
```

**Shared validation helpers:** To prevent semantic drift between `POST /dossier/create` and `GET /dossier/readiness`, extract the per-edge validation checks from `_validate_dossier_edges()` into reusable sub-check functions:

```python
# In dossier.py — shared validation helpers

def _check_edge_schema(cred, edge_def) -> bool:
    """Check if credential matches edge schema constraint."""
    if edge_def.get("schema") and cred.schema_said != edge_def["schema"]:
        return False
    return True

def _check_edge_i2i(cred, org_aid, edge_def) -> bool:
    """Check I2I: credential recipient_aid must match org AID."""
    if edge_def.get("operator") == "I2I" and cred.recipient_aid != org_aid:
        return False
    return True

def _check_edge_status(cred) -> bool:
    """Check credential is not revoked."""
    return cred.status != "revoked"

def _check_delsig_semantics(cred, org_aid) -> bool:
    """Check delsig-specific rules: issuer must be AP."""
    return cred.issuer_aid == org_aid and cred.recipient_aid is not None
```

Both `_validate_dossier_edges()` (create flow) and `dossier_readiness()` use these helpers. The create flow validates specific credential SAIDs; the readiness flow iterates all candidates and counts how many pass.

**Key difference from Sprint 63 `_validate_dossier_edges`:** The readiness endpoint does NOT initialize KERI or require specific credential SAIDs — it checks whether *any* credential for each slot *could* satisfy dossier creation constraints. This is a "can we build a dossier?" check, not a "validate these specific credentials" check.

**Known limitation — slot-level independence:** Readiness evaluates each slot independently (has at least one valid credential per slot). It does NOT check cross-slot compatibility (e.g., whether a specific delsig candidate's OP matches a specific bownr candidate's expectations). This is acceptable because:
1. The conditional bproxy gate (step 5) handles the most important cross-slot dependency
2. Full combination-aware satisfiability would require solving a constraint satisfaction problem across all slot candidates — over-engineering for a preflight check
3. The actual `POST /dossier/create` performs full validation with specific credentials selected by the user
4. False positives are limited to rare cross-slot incompatibility scenarios and are caught at create time

**Single source of truth — clear boundaries:**

| Context | Edge definition source | Why |
|---------|----------------------|-----|
| Dossier readiness endpoint (`GET /dossier/readiness`) | `DOSSIER_EDGE_DEFS` constant | Includes access policies, validation rules, and dossier-specific semantics (delsig AP check, bproxy conditionality) that aren't in schema JSON |
| Dossier create endpoint (`POST /dossier/create`) | `DOSSIER_EDGE_DEFS` constant | Same as above — shared validation helpers ensure consistency |
| Credentials page edge UI (any schema) | `SchemaEdgeParser` (client-side JS) | Generic: parses any schema's edge block. No dossier-specific policies. |
| Schema edge parsing tests (Python) | `parse_schema_edges()` utility | Test-only: validates schema JSON structure matches expectations |

`DOSSIER_EDGE_DEFS` is the **authoritative source** for dossier-specific behavior. `parse_schema_edges()` is a test utility and is NOT used by the readiness endpoint. This eliminates the contradiction.

**Mismatch detection:** The `test_parse_dossier_schema_edges` test (in test_schema_edge_parsing.py) cross-validates that `parse_schema_edges()` output for the dossier schema matches `DOSSIER_EDGE_DEFS` for required/optional flags and schema constraints. If the dossier schema JSON is updated without updating `DOSSIER_EDGE_DEFS`, this test fails — providing a fail-fast contract.

**Response model** (`services/issuer/app/api/models.py`):
```python
class DossierSlotStatus(BaseModel):
    edge: str                           # Edge name
    label: str                          # Human-readable label
    required: bool
    schema_constraint: Optional[str]    # Schema SAID constraint or null
    available_count: int                # Number of credentials passing all checks
    total_count: int                    # Total non-revoked credentials matching schema
    status: str                         # "ready" | "missing" | "invalid" | "optional_missing" | "optional_unconstrained"
    # "ready": >=1 credential passes all dossier-creation checks
    # "missing": required slot with no credentials (blocks readiness)
    # "invalid": non-revoked credentials exist but none pass validation (I2I mismatch, etc.)
    # "optional_missing": optional slot with no credentials (does NOT block readiness)
    # "optional_unconstrained": optional slot with no schema constraint — candidates exist but
    #     suitability requires manual assessment (e.g., bownr/bproxy accept any credential type)

class DossierReadinessResponse(BaseModel):
    org_id: str
    org_name: str
    ready: bool                         # True when all required slots are satisfied
    slots: list[DossierSlotStatus]
    blocking_reason: Optional[str] = None  # Human-readable reason if ready=false (e.g., "Required edge 'tnalloc' is not satisfied")
```

**Frontend: Readiness panel on dossier page**

Add a readiness checklist section to `dossier.html` (below the wizard or as a pre-step):
- For each edge slot: name, required/optional badge, credential count
- Green check if ready, red X with "Create" link if missing
- "Create" link opens `/ui/credentials?schema={SAID}&context=dossier&edge={name}&org={org_id}`

#### Phase 5: Tests

**A. Readiness API tests (`services/issuer/tests/test_dossier_readiness.py`):**
- `test_readiness_all_present` — org with all required credentials passing validation → `ready: true`
- `test_readiness_missing_required` — org missing tnalloc → `ready: false`, tnalloc slot `status: "missing"`
- `test_readiness_revoked_excluded` — revoked credential not counted → `status: "missing"` not `"ready"`
- `test_readiness_optional_missing_ok` — missing bownr doesn't affect overall readiness
- `test_readiness_nonexistent_org` — returns 404
- `test_readiness_access_control` — non-admin can only check own org
- `test_readiness_i2i_mismatch` — credential exists for I2I slot but recipient_aid doesn't match org AID → `status: "invalid"`, `total_count: 1`, `available_count: 0`
- `test_readiness_delsig_issuer_check` — delsig credential exists but issuer is not AP → `status: "invalid"`
- `test_readiness_no_bproxy_advisory_at_readiness_level` — verifies readiness does NOT emit bproxy advisory (deferred to create endpoint)
- `test_readiness_optional_status` — missing bownr → `status: "optional_missing"` (not "missing")

**B. Schema edge parsing tests (`services/issuer/tests/test_schema_edge_parsing.py`):**

A Python `parse_schema_edges()` test utility validates that schema JSON edge blocks are correctly structured. This function is used by tests only (NOT by the readiness endpoint, which uses `DOSSIER_EDGE_DEFS`). It mirrors the JS `SchemaEdgeParser` logic for cross-validation:

- `test_parse_dossier_schema_edges` — Parse dossier schema → returns 6 edge slots (vetting, alloc, tnalloc, delsig required; bownr, bproxy optional) with correct operators and schema constraints
- `test_parse_tnalloc_schema_edges` — Parse TNAlloc schema → returns 2 slots (tnalloc required I2I, issuer optional NI2I)
- `test_parse_gcd_schema_edges` — Parse GCD schema → returns 1 slot (issuer required I2I)
- `test_parse_schema_no_edges` — Parse a schema with no `e` property → returns empty list
- `test_parse_schema_edge_constraints` — Dossier alloc edge has `schemaConstraint = "EL7irIKYJL9..."`, vetting edge has `schemaConstraint = null`
- `test_parse_schema_reordered_oneof` — Schema with `oneOf` where object variant is at index 0 (not 1) → parser still finds it correctly via type-based detection

**C. Edge collection integration tests (`services/issuer/tests/test_credential_edge_integration.py`):**

Tests that validate the end-to-end credential issuance with schema-derived edges:

- `test_issue_with_schema_edges` — Issue a credential with edges matching schema constraints → succeeds
- `test_issue_with_operator_in_payload` — Verify that edges submitted with `o` (operator) field in the edge dict are accepted by `/credential/issue`
- `test_issue_edge_payload_structure` — Verify that the edge payload `{ n: SAID, s: schemaSAID, o: "I2I" }` is correctly passed through to the issued credential's edge block
- `test_issue_merge_schema_and_manual_edges` — Verify that both schema-driven and manual edges can coexist in a single issuance payload
- `test_credential_list_org_filtered` — `GET /credential?org_id=X&schema_said=Y` returns only matching credentials (validates the query used by edge pickers)
- `test_credential_list_relationship_field` — Credentials returned by `GET /credential?org_id=X` include `relationship` field for I2I filtering

**D. Deep-link, admin, and bproxy access tests:**

- `test_readiness_admin_cross_org` — System admin can check readiness for any org
- `test_credential_list_admin_org_scoped` — Admin can filter credentials by org_id for edge candidate loading
- `test_bproxy_principal_scoped` — bproxy credentials are loaded without org_id filter (cross-entity visibility when OP != AP)
- `test_bproxy_not_org_scoped` — When loading edge candidates for bproxy, credentials from OTHER orgs are visible (unlike ap_org edges)
- `test_readiness_bproxy_op_equals_ap` — OP == AP: ready with no advisory
- `test_readiness_op_ne_ap_no_bownr` — OP != AP without bownr: ready with no advisory (gate deferred to create)

**E. Frontend validation via Python integration tests:**

No JS unit test framework exists in this project. Instead, frontend logic correctness is validated through:

1. **Backend contract tests** that validate the same constraints the UI relies on:
   - `parse_schema_edges()` tests verify the schema parsing contract that JS `SchemaEdgeParser` mirrors
   - Credential list filter tests verify `GET /credential?schema_said=...&org_id=...` returns correctly scoped results
   - Edge payload structure tests verify `/credential/issue` accepts `{n, s, o}` edge payloads

2. **Readiness API tests** that exercise the full per-edge validation pipeline server-side, verifying the same logic the UI will rely on for candidate filtering

3. **Manual smoke testing** for UI-specific behavior (rendering, deep links, collectEdges merge, card selection). These are documented in the Implementation Notes appendix after implementation.

This strategy is consistent with all previous sprints (63, 60, 58) which validated UI behavior through backend contract tests + manual verification.

## Scope Boundaries

The following items have been raised during review but are explicitly OUT OF SCOPE for Sprint 65:

1. **Server-side schema-edge validation for `/credential/issue`** — Sprint 65 adds UI-side schema awareness only. The `/credential/issue` endpoint passes edge payloads through to keripy without schema-level validation (existing behavior). Adding server-side schema enforcement is a separate feature and would require its own sprint definition.

2. **Vetting schema constraint** — The dossier schema JSON does NOT constrain the `vetting.s` field to a specific schema SAID (no `const` on `properties.vetting.properties.s`). This is intentional by design: vetting accepts any identity credential type (LE, Extended LE, vLEI QVI, etc.) to support diverse vetting models. `DOSSIER_EDGE_DEFS` correctly sets `schema: None` for vetting, matching the authoritative schema JSON. If the spec evolves to restrict vetting to LE-only, the schema JSON would add a `const` constraint and `DOSSIER_EDGE_DEFS` would be updated accordingly — but that is a spec change, not a Sprint 65 task.

3. **Combination-aware satisfiability checking** — Documented as a known limitation (see readiness endpoint section). Slot-level independence is acceptable for a preflight check.

## Data Flow

### Schema Selection → Edge Rendering
```
User selects schema
  → schemaSelect.change fires
  → SchemaFormGenerator.generateFromSchema(said, container)  [existing]
  → SchemaEdgeParser.parseEdges(currentSchemaDoc)            [new]
  → renderSchemaEdgeSlots(edgeSlots)                         [new]
    → For each slot: loadEdgeCandidates(slot)                [new]
      → GET /credential?schema_said=...&org_id=...
      → Render credential picker with radio buttons
```

### Credential Issuance with Schema Edges
```
User fills form + selects edge credentials
  → Submit button clicked
  → collectAttributes() [existing]
  → collectEdges() [modified to merge schema + manual]
  → POST /credential/issue { ..., edges: { edgeName: { n, s, o } } }
```

### Dossier Readiness Check
```
GET /dossier/readiness?org_id=...
  → Validate org + access
  → For each DOSSIER_EDGE_DEFS slot:
    → Count matching credentials (schema_said + org filter)
  → Return { ready, slots: [...] }
```

## Error Handling

- Schema with no edges: hide edge section, show only attributes form
- No credentials match edge constraint: show "No matching credentials" with "Create" link
- Credential fetch fails: show error toast, don't block form submission (edges are optional for many schemas)
- Readiness endpoint: org not found → 404, access denied → 403

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/issuer/web/credentials.html` | Modify | Add `SchemaEdgeParser`, schema-driven edge UI, credential type cards, recipient AID helper, deep link support |
| `services/issuer/web/dossier.html` | Modify | Add readiness panel, "Create" links for missing credentials |
| `services/issuer/web/shared.js` | Modify | Add schema type label lookup utility (`schemaLabelMap`) |
| `services/issuer/app/api/dossier.py` | Modify | Add `GET /dossier/readiness` endpoint |
| `services/issuer/app/api/models.py` | Modify | Add `DossierSlotStatus`, `DossierReadinessResponse` models |
| `services/issuer/tests/test_dossier_readiness.py` | Create | Readiness endpoint tests |
| `services/issuer/tests/test_schema_edge_parsing.py` | Create | Schema edge block parsing tests |
| `services/issuer/tests/test_credential_edge_integration.py` | Create | Edge collection integration tests |
| `knowledge/api-reference.md` | Update | Document readiness endpoint |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Schema edge block format varies across schemas | Low | Medium | Verified: all 13 schemas use consistent `e.oneOf[1]` pattern. Parser handles missing/empty edges gracefully. |
| Edge credential loading is slow (many API calls) | Medium | Low | Load credentials per-slot only on expand (lazy). Cache responses. |
| `collectEdges()` merge conflicts between schema and manual edges | Low | Medium | Schema edges take precedence. Manual edges only for names not in schema. Clear UI separation. |
| Readiness endpoint exposes credential counts | Low | Low | Same access control as existing credential list endpoint (org-scoped). |

## Implementation Order

1. **SchemaEdgeParser class** — Pure parsing, no UI dependencies
2. **Schema type label map** — Utility needed by edge UI
3. **Schema-driven edge UI** — Main feature (rendering + credential pickers)
4. **collectEdges() merge** — Wire up to form submission
5. **Credential type cards** — Quick-create templates
6. **Deep link support** — `?schema=...&context=dossier` params
7. **Recipient AID helper** — Org picker for `a.i` field
8. **Readiness API endpoint** — Backend + Pydantic models
9. **Readiness panel in dossier.html** — Frontend integration
10. **Tests** — Readiness endpoint tests
11. **Knowledge updates** — api-reference.md
