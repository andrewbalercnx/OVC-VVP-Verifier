# Sprint 66: Knowledge Base & Documentation Refresh + Interactive Walkthrough

## Problem Statement

The knowledge base serves three audiences: Claude Code (Tiers 1-3), the Codex Reviewer (context pack), and human developers. Sprints 58-65 introduced significant features that are not fully reflected in the documentation, causing stale context during pair programming and reviews. Additionally, there is no guided onboarding experience for new users of the issuer UI.

## Scope

**Note:** The Sprint 66 definition in `SPRINTS.md` has been updated (at the start of this sprint, per user request) to include the interactive walkthrough as Phase 5, changing Sprint 66 from "documentation-only" to "primarily documentation with one lightweight UI addition." The SPRINTS.md technical notes section was also updated from "No code changes" to "Minimal code changes" to reflect this. The walkthrough is a standalone HTML page with minimal backend changes (one route in `main.py`, one exempt-path addition in `config.py`).

**Sprint scope reconciliation:** The original Sprint 66 definition in `SPRINTS.md` said "no code changes, only documentation." This was updated during sprint planning (at the user's request) to "minimal code changes" to accommodate the walkthrough addition. The `SPRINTS.md` goal, technical notes, dependencies, and exit criteria sections have ALL been updated to consistently say "minimal code changes" and reference the walkthrough's backend plumbing (one route, one auth-exempt path). There is no remaining contradiction in the governing sprint record.

This sprint has two components:
1. **Documentation refresh** (Phases 1-4, 6) — Audit and update all knowledge files, service CLAUDE.md guides, and reviewer context packs to reflect the current codebase.
2. **Interactive walkthrough** (Phase 5) — A split-pane walkthrough page where one pane shows tutorial content and the other shows the live UI in an iframe.

## Current State

### Documentation Gaps Identified (from codebase audit)

| File | Last Update | Key Gaps |
|------|-------------|----------|
| `services/issuer/CLAUDE.md` | ~Sprint 53 | Missing: dossier wizard, readiness API, schema-driven credential UI, vetter certification, org API keys, SSO auth, all Sprint 58-65 features |
| `services/verifier/CLAUDE.md` | ~Sprint 40 | Missing: vetter constraint phase, INDETERMINATE status, callee parity, dossier public access |
| `common/CLAUDE.md` | ~Sprint 40 | Missing: SIP models (vetter_status), updated schema registry entries |
| `knowledge/api-reference.md` | Sprint 65 (partial) | Missing ~40 issuer endpoints (org API keys, vetter cert CRUD, admin settings, dashboard, user management, constraints visibility) |
| `knowledge/data-models.md` | Sprint 65 (partial) | Missing: OrgAPIKey*, UserOrgRole, MockVLEIState.gsma_*, VetterCert models, DossierSlotStatus, DossierReadinessResponse |
| `knowledge/architecture.md` | ~Sprint 40 | Missing: issuer multi-tenancy, SSO auth, dossier assembly pipeline, SIP infrastructure, vetter constraint flow |
| `knowledge/schemas.md` | ~Sprint 40 | Missing: dossier schema, extended schemas, vetter certification schema, GSMA governance schema |
| `knowledge/deployment.md` | ~Sprint 53 | Missing: LMDB lock handling, OIDC migration, new repo URL, 4-phase stop |
| `knowledge/test-patterns.md` | ~Sprint 40 | Missing: issuer test patterns, async fixtures, mock credential helpers, VARCHAR(44) constraint |
| `knowledge/verification-pipeline.md` | ~Sprint 40 | Missing: vetter constraint evaluation (Phase 11), INDETERMINATE handling |
| `knowledge/dossier-creation-guide.md` | N/A | Does not exist — needs creation |
| `codex/.../source-map.md` | ~Sprint 53 | Missing: vetter package, SIP services, Sprint 58-65 files |
| `codex/.../vvp.md` | ~Sprint 53 | Missing: dossier readiness, vetter constraints, signing-time enforcement |

### Walkthrough Gap

No guided onboarding exists. New users must discover the UI by clicking through pages. The help page has static documentation but no interactive walkthrough.

## Non-Goals / Explicit Exclusions

- **SIP services — SIP/UDP handlers:** The SIP redirect and verify services primarily handle raw UDP SIP messages, which are not REST endpoints. However, they DO expose HTTP operational endpoints (e.g., `/status`, `/health`, `/api/events/ingest` in sip-redirect). These will be documented in `knowledge/api-reference.md` under a "SIP Operational Endpoints" section, extracted from `services/sip-redirect/app/status.py` and `services/sip-redirect/app/monitor/server.py`.
- **Standalone verifier (vvp-verifier-oss):** An orphan-branch project with its own documentation lifecycle.
- **keripy vendored library:** Internal dependency, not part of VVP knowledge base.

## Proposed Solution

### Phase 1: Tier 2 Service CLAUDE.md Files

These are auto-loaded when working in a service directory — highest impact.

#### 1a. `services/issuer/CLAUDE.md` — Full Rewrite

Read the actual code for each router and document:

- **API routers** (15 routers mounted via `app.include_router()` in `main.py:325-339`):

  **Endpoint extraction method:** Each route's full path = router `prefix=` + decorator path. NO router uses an `/api/` prefix in its router definition. The 15 routers and their prefixes are:

  | # | Router File | `prefix=` | Notes |
  |---|-------------|-----------|-------|
  | 1 | `health.py` | (none) | Single route: `/healthz` |
  | 2 | `dashboard.py` | (none) | Path hardcoded in decorator: `/api/dashboard/status` |
  | 3 | `auth.py` | `/auth` | 6 auth routes |
  | 4 | `identity.py` | `/identity` | 6 identity CRUD routes |
  | 5 | `organization.py` | `/organizations` | 5 org management routes |
  | 6 | `org_api_key.py` | `/organizations/{org_id}/api-keys` | 4 key CRUD routes |
  | 7 | `user.py` | `/users` | 8 user management routes |
  | 8 | `registry.py` | `/registry` | 4 registry CRUD routes |
  | 9 | `schema.py` | `/schema` | 8 schema management routes |
  | 10 | `credential.py` | `/credential` | 5 credential routes |
  | 11 | `dossier.py` | `/dossier` | 6 dossier routes |
  | 12 | `vvp.py` | `/vvp` | 1 attestation route |
  | 13 | `tn.py` | `/tn` | 6 TN mapping routes |
  | 14 | `vetter_certification.py` | (none) | 6 routes with paths hardcoded in decorators |
  | 15 | `admin.py` | `/admin` | 4+ admin routes |

  **During implementation**, the exact endpoint inventory will be machine-extracted by walking each router file's `@router.<method>("...")` decorators and prepending the prefix. This plan does NOT hardcode individual endpoint paths — the authoritative source is the code itself.

- **Authentication model**: SSO (Azure AD/M365 OAuth), API keys (file-based + org-scoped DB), session cookies, Principal model, role hierarchy (issuer:admin > operator > readonly; org:administrator > dossier_manager)

- **Database models**: Organization, User, UserOrgRole, OrgAPIKey/Role, ManagedCredential, MockVLEIState, TNMapping, DossierOspAssociation

- **Key architecture patterns**: Multi-tenancy via org scoping, mock vLEI infrastructure (GLEIF→QVI→LE chain + GSMA→VetterCert chain), dossier assembly pipeline, credential issuance with edge injection, SIP redirect signing flow

- **UI pages**: 18 HTML pages under /ui/*, static assets via /static/ mount

#### 1b. `services/verifier/CLAUDE.md` — Refresh

Update the existing content to reflect:
- Phase 11 vetter constraint evaluation (Sprint 40/62)
- INDETERMINATE status for vetter constraint failures
- Callee verification parity (verify_callee.py now has Phase 11)
- Dossier public access endpoint
- Brand name/logo extraction from PASSporT card claim (Sprint 44/58)
- issuer_identities and vetter_constraints in VerifyResponse
- Updated ErrorCode registry (extract count from `services/verifier/app/vvp/api_models.py` — do not hardcode; includes VETTER_* codes added in Sprint 40/62)

#### 1c. `common/CLAUDE.md` — Refresh

Update to reflect:
- SIP models: SIPRequest + SIPResponse with vetter_status field, builder module
- Schema registry updates (any new schema SAIDs)
- Dossier models: EdgeOperator, ToIPWarningCode enums fully listed

### Phase 2: Tier 3 Knowledge Files

#### 2a. `knowledge/api-reference.md` — Comprehensive Endpoint Audit

Walk every FastAPI router in both services. The issuer has 15 routers (see Phase 1a table). The verifier defines endpoints directly in `main.py`. Document each endpoint with HTTP method, full path, auth requirement, request/response models, and query parameters.

**Endpoint extraction method:** Three source categories:

1. **Issuer router endpoints:** For each router file in `services/issuer/app/api/*.py`, extract all `@router.<method>("<path>")` decorators and prepend the router's `prefix=` argument. For routers with no prefix (`health.py`, `dashboard.py`, `vetter_certification.py`), the decorator path IS the full path. Cross-check mount order in `main.py:325-339`.

2. **Issuer main.py endpoints:** `services/issuer/app/main.py` defines additional endpoints directly via `@app.get(...)` decorators — these include UI routes (`/ui/*`), legacy routes (`/create`, `/registry/ui`, etc.), the root route (`/`), and operational routes (`/version`). These MUST be included in the endpoint inventory alongside router-provided endpoints.

3. **Verifier endpoints:** Extract all `@app.<method>("<path>")` decorators from `services/verifier/app/main.py`.

All endpoint paths will be extracted from code during implementation — no hardcoded path assumptions in this plan. Key sections to document include: organization API keys, user management, vetter certification CRUD, admin settings, dashboard health, dossier CRUD/readiness/build, schema management, TN mapping, and verifier proxy/graph/HTMX endpoints.

#### 2b. `knowledge/data-models.md` — Comprehensive Model Audit

Document all 93 model classes across:
- 11 SQLAlchemy models (issuer DB)
- ~60 Pydantic models (issuer API)
- ~17 Pydantic models + enums (verifier API)
- 5 dataclasses (common library)

#### 2c. `knowledge/architecture.md` — Major Update

Add:
- Issuer service architecture (Sprint 28+)
- Multi-tenancy model (Organization as tenant root)
- SSO authentication flow (M365 OAuth + session cookies)
- Mock vLEI infrastructure (GLEIF→QVI→LE + GSMA→VetterCert dual chains)
- Dossier assembly pipeline (credential chain → dossier build → CESR/JSON)
- SIP infrastructure (signing@5070 → verify@5071 → brand display)
- Vetter constraint flow (issuance → dossier → signing → verification)
- Updated system diagram

#### 2d. `knowledge/schemas.md` — Schema Registry Refresh

List every schema JSON in `services/issuer/app/schema/schemas/`:
- Base schemas: LE, QVI, Brand, TNAlloc, GCD, Dossier (CVD)
- Extended schemas: Extended LE, Extended Brand, Extended TNAlloc
- Infrastructure schemas: VetterCertification, GSMA Governance
- Each with: SAID, title, edge structure, attribute fields, purpose

#### 2e. `knowledge/deployment.md` — Deployment Refresh

**Sync rule:** `Documentation/DEPLOYMENT.md` remains the canonical deployment source of truth (per Sprint 55/56 decisions — used for URL/port/config validation gates). `knowledge/deployment.md` is a synchronized Tier 3 reference derived from it for Claude Code context. During this sprint, update `knowledge/deployment.md` to reflect current deployment reality, and ensure it does not conflict with `Documentation/DEPLOYMENT.md`. If discrepancies are found, `Documentation/DEPLOYMENT.md` takes precedence and should be updated first, then `knowledge/deployment.md` synchronized.

Update:
- New repo URL (Rich-Connexions-Ltd/VVP)
- OIDC federated auth (replaces static credentials)
- LMDB lock handling (4-phase stop procedure)
- Azure Container App configuration
- PBX deployment via Azure CLI
- Azure Blob Storage for deployments

#### 2f. `knowledge/test-patterns.md` — Test Pattern Refresh

Add:
- Issuer test patterns (async fixtures, mock credential helpers)
- `_full_cred_set()` helper pattern for dossier readiness tests
- PostgreSQL VARCHAR(44) constraint for SAID fields
- Test organization/user/credential setup fixtures
- `run-tests.sh` wrapper and libsodium setup

#### 2g. `knowledge/verification-pipeline.md` — Verify and Update

Confirm 11-phase description matches current code. Add:
- Phase 11 vetter constraint evaluation details
- INDETERMINATE status for vetter failures
- Dossier public access verification flow
- Brand extraction from card claim

#### 2h. `knowledge/keri-primer.md` — Verify (minimal changes expected)

#### 2i. `knowledge/dossier-parsing-algorithm.md` — Verify (likely current)

#### 2j. `knowledge/dossier-creation-guide.md` — NEW FILE

Step-by-step guide covering both operational models:

**Model 1: Without Vetter Certification**
- Prerequisites, credential chain (QVI → LE → Brand, TNAlloc), base schemas
- API calls: POST /credential/issue for each, POST /dossier/create for assembly

**Model 2: With Vetter Certification (Sprint 61/62)**
- Prerequisites + VetterCertification from GSMA
- Extended schemas with auto-injected certification edges
- Constraint semantics (ECC targets, jurisdiction targets)

### Phase 3: Tier 1 Root Files

#### 3a. `CLAUDE.md` — Incremental Update

- Verify project structure tree matches actual directory layout
- Add any new key files or directories (vetter package, dashboard, etc.)
- Verify all script references are accurate
- Update service URLs table if needed

#### 3b. Auto-memory `MEMORY.md` — Out of scope (verify only)

Location: `/Users/andrewbale/.claude/projects/-Users-andrewbale-Azure-VVP/memory/MEMORY.md`

MEMORY.md is a Claude Code auto-memory artifact outside the repo. It is NOT a Sprint 66 deliverable. During implementation, read it and flag any obviously wrong facts (e.g., stale sprint references, incorrect endpoint paths), but repo-tracked knowledge files remain the canonical documentation. Any MEMORY.md corrections are non-blocking side-effects.

### Phase 4: Reviewer Context Pack

#### 4a. `codex/skills/keri-acdc-vlei-vvp/references/source-map.md` — Update

Reflect current file layout:
- Add `app/vetter/` package (service.py, constants.py, constraints.py)
- Add `app/api/vetter_certification.py`, `app/api/dashboard.py`
- Add `app/db/migrations/` directory
- Update web/ file list (18 HTML pages)
- Add SIP service entries

#### 4b. `codex/skills/keri-acdc-vlei-vvp/references/vvp.md` — Update

(Note: The VVP reference file is `vvp.md`, not `vvp-reference.md`. The `SPRINTS.md` exit criteria have been corrected to use the canonical filename `vvp.md`.)

Reflect current API surface:
- Add dossier readiness endpoint (`GET /dossier/readiness`)
- Add vetter constraint enforcement flow
- Add signing-time constraint validation
- Update dossier edge structure (certification edge)

### Phase 5: Interactive Split-Pane Walkthrough

#### Design

Create `services/issuer/web/walkthrough.html` — a standalone HTML page with:

**Layout:**
```
┌─────────────────────────────────┐
│  VVP Guided Walkthrough         │
├───────────────┬─────────────────┤
│               │                 │
│  Tutorial     │   Live UI       │
│  Content      │   (iframe)      │
│  (left pane)  │   (right pane)  │
│               │                 │
│  ← Prev Next →│                 │
│               │                 │
└───────────────┴─────────────────┘
```

**Implementation:**

1. **Step data structure** — A JS array of step objects:
   ```js
   const WALKTHROUGH_STEPS = [
     {
       title: "Welcome to VVP Issuer",
       content: "<p>The VVP Issuer manages...</p>",
       uiPath: "/ui/",
       highlights: []  // CSS selectors to highlight in iframe (future)
     },
     ...
   ];
   ```

2. **Walkthrough content** — 8-10 steps covering the main user journeys:
   | Step | Title | UI Path | Content Focus |
   |------|-------|---------|---------------|
   | 1 | Welcome | `/ui/` | Overview of VVP Issuer, navigation |
   | 2 | Organizations | `/organizations/ui` | Multi-tenancy, creating an org (legacy route pattern) |
   | 3 | Identity Management | `/ui/identity` | KERI identities, AIDs, OOBI |
   | 4 | Schema Browser | `/ui/schemas` | Schema types, edge definitions |
   | 5 | Credential Issuance | `/ui/credentials` | Schema-driven forms, edge linking |
   | 6 | Dossier Assembly | `/ui/dossier` | Readiness check, wizard, edge selection |
   | 7 | VVP Attestation | `/ui/vvp` | PASSporT creation, VVP-Identity header |
   | 8 | Service Dashboard | `/ui/dashboard` | Health monitoring, service status |
   | 9 | Vetter Certification | `/ui/vetter` | Constraint management (advanced) |
   | 10 | Help & Recipes | `/ui/help` | Additional documentation |

3. **Left pane** — Renders the current step's content as HTML. Shows step number, title, explanatory text, and navigation buttons (Previous/Next). Progress indicator at top.

4. **Right pane** — An `<iframe>` that loads `uiPath` for the current step. When the user clicks Next/Previous, the iframe src updates automatically.

5. **Responsive design** — CSS Grid layout with a draggable divider (using CSS `resize: horizontal` on the left pane, or a simple JS drag handler). On narrow screens (<768px), stacks vertically.

6. **Styling** — Follows existing `styles.css` patterns (VVP color scheme, card styling). No new CSS framework.

7. **Route** — Add `/ui/walkthrough` route in `main.py`, serving `walkthrough.html`.

8. **Navigation link** — Add "Walkthrough" link to the navigation markup in each HTML page that includes nav links (the existing pattern is page-local `<nav>` markup, not a shared template). At minimum, add the link to `index.html` (home page) and `help.html`.

**Constraints:**
- No external dependencies (vanilla JS, no framework)
- iframe same-origin (all /ui/* paths are on the same host)
- Minimal backend changes: one route in `main.py` (`/ui/walkthrough` → `walkthrough.html`), one exempt-path addition in `config.py`. **Rationale:** All UI pages in the issuer are served via `@app.get("/ui/<name>")` handlers in `main.py` that return `HTMLResponse` from the `web/` directory — there is no static file serving for HTML pages. Adding the walkthrough follows the identical pattern used by all 15+ existing UI routes. The auth-exempt addition follows the same `get_auth_exempt_paths()` pattern used by every other UI route. These are not new patterns or architectural decisions; they are mandatory plumbing for any new UI page in this application.
- Step data is static JS embedded in the HTML — no backend API for walkthrough content
- Content is static HTML strings — no Markdown rendering needed

**Auth behavior — follows existing `UI_AUTH_ENABLED` pattern (no policy departure):**

The walkthrough follows the established auth model from Sprint 52. The `get_auth_exempt_paths()` function in `services/issuer/app/config.py:344-386` centralizes all exemptions. The walkthrough route is added to the `UI_AUTH_ENABLED=false` block alongside all other `/ui/*` routes.

- **`UI_AUTH_ENABLED=false` (default local dev):** `/ui/walkthrough` is added to the exempt-paths set in `get_auth_exempt_paths()`, alongside `/ui/`, `/ui/identity`, `/ui/dashboard`, etc. Both the walkthrough page and all iframe pages load without auth. Full walkthrough experience works.
- **`UI_AUTH_ENABLED=true` (production):** `/ui/walkthrough` is NOT exempt — it requires authentication, exactly like every other `/ui/*` route. Once the user is authenticated, both the walkthrough page and iframe pages work normally (session cookie applies to all same-origin requests).

**Implementation detail:** Add one line to `get_auth_exempt_paths()` in the `if not UI_AUTH_ENABLED:` block:
```python
exempt.add("/ui/walkthrough")
```
This is the same pattern used for `/ui/dashboard`, `/ui/admin`, and all other UI routes. No security exception or special case is needed.

**Acceptance Checklist:**
1. `/ui/walkthrough` loads without errors (200 status)
2. Each step's iframe loads the correct UI path (verify src attribute)
3. Previous/Next buttons navigate between all steps correctly
4. Progress indicator shows current step out of total
5. **Auth handling:** Walkthrough follows `UI_AUTH_ENABLED` — when `true`, requires auth like all other `/ui/*` routes; when `false`, accessible without auth. No special exemption or policy departure
6. **Missing page fallback:** If a step's `uiPath` returns 404, the iframe displays the standard 404 page (no crash)
7. **Mobile layout:** On viewports <768px, panes stack vertically (tutorial above, iframe below)
8. **Resize:** The left pane can be resized by dragging the divider (desktop only)

### Phase 6: Consistency Verification

Executable cross-reference checks with concrete pass/fail outputs:

#### 6a. Endpoint Coverage Matrix
**Method:** Build two sets and compare:

1. **Code set:** Combine endpoints from three issuer sources plus verifier:
   - **Issuer routers:** For each file in `services/issuer/app/api/*.py`, extract `{HTTP_METHOD, prefix + path}` from `@router.<method>("<path>")` decorators.
   - **Issuer main.py:** For `services/issuer/app/main.py`, extract `{HTTP_METHOD, path}` from `@app.get("<path>")` decorators (UI routes, legacy routes, root, version, etc.).
   - **Verifier main.py:** For `services/verifier/app/main.py`, extract `{HTTP_METHOD, path}` from `@app.<method>("<path>")` decorators.
   - **SIP operational:** Extract from `services/sip-redirect/app/status.py` and `services/sip-redirect/app/monitor/server.py` if present on disk (SIP services may not be in this repo).

   The union of all extracted tuples produces the authoritative `code_endpoints` set.

2. **Doc set:** From `knowledge/api-reference.md`, extract `{HTTP_METHOD, path}` tuples from each documented endpoint row. This produces the `doc_endpoints` set.

3. **Compare:**
   - `missing = code_endpoints - doc_endpoints` → endpoints in code but not documented
   - `extra = doc_endpoints - code_endpoints` → documented endpoints that don't exist in code
   - Report both sets as tables

**Pass criterion:** Both `missing` and `extra` sets are empty (exact match on `{method, path}` pairs).

#### 6b. Model Coverage Matrix
**Method:** Extract model classes from all four source categories using appropriate patterns:
- **SQLAlchemy models:** `class <Name>(Base):` in `services/issuer/app/db/models.py`
- **Pydantic models:** `class <Name>(BaseModel):` (and subclasses like `BaseModel`, custom bases) in `services/issuer/app/api/models.py` and `services/verifier/app/vvp/api_models.py`
- **Dataclasses:** `@dataclass` decorated classes in `common/common/vvp/models/*.py`
- **Enums:** `class <Name>(str, Enum):` or `class <Name>(Enum):` in all model files

For each extracted class name, grep `knowledge/data-models.md` for it. Report as a table:

| Source File | Model Class | Documented? |
|-------------|-------------|-------------|
| `db/models.py` | `Organization` | YES/NO |

**Pass criterion:** Zero undocumented model classes.

#### 6c. Schema Coverage Matrix
**Method:** List all `.json` files in `services/issuer/app/schema/schemas/`. For each, extract the SAID (`$id` field). Grep `knowledge/schemas.md` for each SAID. Report as a table:

| Schema File | SAID | Documented? |
|-------------|------|-------------|
| `tnalloc.json` | `EFvnoHDY7I-...` | YES/NO |

**Pass criterion:** Zero undocumented schemas.

#### 6d. Environment Variable Coverage
**Method:** Extract all `os.getenv("VAR_NAME")` and `os.environ.get("VAR_NAME")` calls from `services/issuer/app/config.py`, `services/verifier/app/core/config.py`, and `.github/workflows/deploy.yml`. Check each variable name appears in `knowledge/deployment.md`. Report as a table:

| Source File | Env Var | Documented? |
|-------------|---------|-------------|
| `config.py` | `VVP_ISSUER_BASE_URL` | YES/NO |

**Pass criterion:** All configuration-relevant env vars are documented (internal/framework vars like `PATH`, `HOME` are excluded).

#### 6e. Directory Structure Verification
**Method:** Run `ls -R` on key directories and compare against the project structure tree in `CLAUDE.md`. Report any directories present in code but missing from the tree.

**Pass criterion:** No significant directories missing from CLAUDE.md tree.

#### 6f. Unresolved Items List
Compile a final list of any items that could not be verified or remain uncertain, with a brief explanation for each. An empty list means full pass.

#### 6g. Reproducible Verification Script

Create `scripts/check-doc-coverage.sh` — a shell script that automates checks 6a-6d (all four automated checks in a single script):

```bash
#!/bin/bash
# Phase 6 documentation coverage checker
# Automates checks 6a (endpoints), 6b (models), 6c (schemas), 6d (env vars)
# Each check outputs its own PASS/FAIL verdict

OVERALL=0  # exit code: 0=all pass, 1=any fail

echo "=== 6a. Endpoint Coverage ==="
# Extract @router.method("path") from issuer routers (services/issuer/app/api/*.py)
# Extract @app.get("path") from issuer main.py (UI, legacy, root, version routes)
# Extract @app.method("path") from verifier main.py
# Extract @app.method("path") from SIP status/monitor (if present on disk)
# Compare against knowledge/api-reference.md entries
# Report missing/extra
# PASS if both missing and extra sets are empty

echo "=== 6b. Model Coverage ==="
# Extract class(BaseModel), class(Base), @dataclass, class(Enum) from model files
# Check each class name appears in knowledge/data-models.md
# Report undocumented models
# PASS if zero undocumented models

echo "=== 6c. Schema Coverage ==="
# List *.json in services/issuer/app/schema/schemas/
# Extract $id from each
# Check SAID appears in knowledge/schemas.md
# Report undocumented schemas
# PASS if zero undocumented schemas

echo "=== 6d. Environment Variable Coverage ==="
# Extract os.getenv/os.environ.get from config files and deploy.yml
# Check each var appears in knowledge/deployment.md
# Exclude framework vars (PATH, HOME, PYTHONPATH, etc.)
# Report undocumented vars
# PASS if zero undocumented config vars

echo "=== Summary ==="
# Print per-section PASS/FAIL and overall verdict
exit $OVERALL
```

Each section prints its own PASS/FAIL line. The script exits 0 only if all four checks pass. Checks 6e (directory structure) and 6f (unresolved items) remain manual and are recorded directly in the report.

#### 6h. Deliverable Format
Phase 6 results are written to a dedicated report file: `Documentation/doc-coverage-report-sprint66.md`. This keeps the plan immutable and the report reviewable as a separate artifact.

The report contains:
1. Script output from `scripts/check-doc-coverage.sh` (stdout capture)
2. Endpoint coverage matrix (table with YES/NO per `{method, path}` pair, including SIP operational endpoints)
3. Model coverage matrix (table with YES/NO per model class)
4. Schema coverage matrix (table with YES/NO per schema SAID)
5. Environment variable coverage matrix (table with YES/NO per env var)
6. Directory structure diff (any missing entries)
7. Manual reconciliation results (targeted spot-checks for edge cases)
8. Unresolved items list (empty = full pass)
9. Overall PASS/FAIL verdict

The verification script uses **Python AST-based extraction** (not regex) for endpoints and models, eliminating multiline-decorator and formatting blind spots:

- **Endpoints:** A Python helper (`python3 -c "import ast; ..."`) parses each source file's AST, finds all `@router.<method>("path")` and `@app.<method>("path")` decorated functions, and extracts `{method, path}` tuples. Router prefix is extracted from `APIRouter(prefix=...)` in the same file's AST. This correctly handles multiline decorators, aliased imports, and keyword arguments. Issuer `main.py` direct routes are included as a separate source.
- **Models:** A Python AST helper walks each model file and extracts all `class <Name>(...)` definitions where base classes include `BaseModel`, `Base`, `Enum`, `str, Enum`, `IntEnum`, etc. For dataclasses, it detects `@dataclass` decorators on class definitions. Excludes internal/private classes (prefixed with `_`).
- **Schemas:** Parse `$id` field from JSON files using `python3 -c "import json; ..."`.
- **Env vars:** Regex extraction of `os.getenv("...")` and `os.environ.get("...")` patterns (simple enough that regex is reliable).
- **False positive mitigation:** Each extracted item is verified by exact-match search in the target doc (not substring), and the report flags any ambiguous matches for manual review.
- **Dynamically generated routes:** The AST approach cannot detect routes registered at runtime via loops or metaprogramming. These are expected to be rare (none known currently) and are called out in the script header as a known limitation.
- **Full reconciliation for low-confidence items:** Any item where the AST parser reports uncertainty (computed decorator arguments, star imports, indirection) triggers mandatory manual verification — not sampling.
- **Manual reconciliation step:** After running the script, manually verify:
  - All items flagged as low-confidence by the AST parser (full, not sampled)
  - At least 10 additional spot-checks (including 2 from `main.py` direct routes, 2 from prefixless routers, 2 dataclasses, 2 enums)
  - All schemas (small set, full verification)
  - All env vars flagged as undocumented
  Record reconciliation results in the report with specific file:line references for each checked item.

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/issuer/CLAUDE.md` | Rewrite | Full service documentation refresh |
| `services/verifier/CLAUDE.md` | Modify | Add vetter constraints, INDETERMINATE, callee parity |
| `common/CLAUDE.md` | Modify | Add SIP models, update schema registry |
| `knowledge/api-reference.md` | Rewrite | All endpoints across both services (count discovered during extraction) |
| `knowledge/data-models.md` | Rewrite | All model classes (count discovered during extraction) |
| `knowledge/architecture.md` | Major update | Add issuer, multi-tenancy, SIP, vetter |
| `knowledge/schemas.md` | Rewrite | All schema JSONs with SAIDs and structure |
| `knowledge/deployment.md` | Update | New repo, OIDC, LMDB lock, 4-phase stop |
| `knowledge/test-patterns.md` | Update | Issuer patterns, fixtures, VARCHAR(44) |
| `knowledge/verification-pipeline.md` | Update | Phase 11, INDETERMINATE, brand extraction |
| `knowledge/keri-primer.md` | Verify | Minimal changes expected |
| `knowledge/dossier-parsing-algorithm.md` | Verify | Likely current |
| `knowledge/dossier-creation-guide.md` | Create | Two-model dossier creation guide |
| `codex/skills/keri-acdc-vlei-vvp/references/source-map.md` | Update | Current file layout |
| `codex/skills/keri-acdc-vlei-vvp/references/vvp.md` | Update | Current API surface |
| `CLAUDE.md` | Update | Project structure verification |
| `services/issuer/web/walkthrough.html` | Create | Interactive split-pane walkthrough |
| `services/issuer/app/main.py` | Modify | Add /ui/walkthrough route |
| `services/issuer/tests/test_walkthrough.py` | Create | Automated route test for /ui/walkthrough |
| `scripts/check-doc-coverage.sh` | Create | Reproducible Phase 6 verification script |
| `Documentation/doc-coverage-report-sprint66.md` | Create | Phase 6 coverage report artifact |

## Implementation Order

1. Phase 5 (Walkthrough) — The only code change; do first so code review covers it
2. Phase 1 (Tier 2 CLAUDE.md files) — Highest impact, used by Claude Code
3. Phase 2 (Tier 3 Knowledge files) — Deep reference docs
4. Phase 3 (Tier 1 Root files) — CLAUDE.md, MEMORY.md
5. Phase 4 (Reviewer Context Pack) — Codex references
6. Phase 6 (Consistency Verification) — Final cross-check

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Stale docs — information read from code is misunderstood | Low | Medium | Read code before writing docs; verify against tests |
| Walkthrough iframe blocked by CSP | Low | Low | Same-origin frames; no CSP headers set currently |
| Large changeset overwhelms reviewer | Medium | Low | Documentation-only changes are low-risk; walkthrough is standalone |
| Context pack exceeds line budget | Medium | Medium | Keep references concise; monitor line counts |

## Test Strategy

- **Walkthrough — automated** (in `services/issuer/tests/test_walkthrough.py`): FastAPI `TestClient` tests covering:
  1. `GET /ui/walkthrough` returns 200 with `text/html` content type
  2. Response body contains expected structural elements (walkthrough container, step navigation, iframe element)
  3. **Step data verification**: Response body contains the `WALKTHROUGH_STEPS` JS array with all expected step entries (verify each step's `uiPath` matches a known UI route)
  4. **Navigation elements**: Response contains Previous/Next buttons and a progress indicator
  5. **Auth-mode behavior**: Test with `UI_AUTH_ENABLED=false` (default) — walkthrough accessible without auth. Test with `UI_AUTH_ENABLED=true` — walkthrough returns 401/redirect when unauthenticated (same pattern as other `/ui/*` route tests)

- **Walkthrough — manual acceptance** (not automated, recorded in report):
  - Mobile layout stacking (<768px viewport)
  - Resizable pane divider behavior
  - Missing page fallback (404 in iframe)

- **Documentation**: No automated tests — accuracy verified by cross-reference check (Phase 6), results committed as a reviewable artifact.

- **Existing tests**: All existing tests must continue to pass (no regressions from main.py route addition)

## Exit Criteria

- All Tier 2 CLAUDE.md files accurately describe their service's current API and architecture
- `knowledge/api-reference.md` documents every endpoint in both services
- `knowledge/data-models.md` documents every model class
- `knowledge/schemas.md` lists every schema with SAID, purpose, and edge structure
- `knowledge/architecture.md` includes issuer service, multi-tenancy, SSO, SIP, and vetter constraints
- `knowledge/deployment.md` reflects current CI/CD pipeline
- `knowledge/dossier-creation-guide.md` provides step-by-step instructions for both dossier models
- Cross-reference check passes
- Interactive walkthrough page loads at `/ui/walkthrough` with split-pane layout
- Walkthrough steps cover main user journeys
- Right pane iframe updates correctly on step transitions
- All existing tests pass

## Definition of Done Evidence

The following artifacts are required for code review acceptance:

| Artifact | Location | Content |
|----------|----------|---------|
| Endpoint coverage report | `Documentation/doc-coverage-report-sprint66.md` §1 | `scripts/check-doc-coverage.sh` output showing PASS for endpoint parity |
| Model coverage report | `Documentation/doc-coverage-report-sprint66.md` §2 | Model class coverage matrix (all YES) |
| Schema coverage report | `Documentation/doc-coverage-report-sprint66.md` §3 | Schema SAID coverage matrix (all YES) |
| Env var coverage report | `Documentation/doc-coverage-report-sprint66.md` §4 | Environment variable coverage matrix (all YES) |
| Walkthrough test results | pytest output in implementation notes | `test_walkthrough.py` — all 5 automated tests pass |
| Manual acceptance checklist | `Documentation/doc-coverage-report-sprint66.md` §5 | Walkthrough manual checks (mobile, resize, 404 fallback) |

## Appendix: Documentation Source of Truth

To prevent path/contract drift in future documentation refreshes, the authoritative source files are:

| Artifact | Authoritative Source | Extraction Method |
|----------|---------------------|-------------------|
| API routes (issuer) | `services/issuer/app/api/*.py` | `@router.<method>("<path>")` + router `prefix=` |
| API routes (verifier) | `services/verifier/app/main.py` | `@app.<method>("<path>")` decorators |
| Router mount order | `services/issuer/app/main.py:325-339` | `app.include_router()` calls |
| DB models | `services/issuer/app/db/models.py` | `class <Name>(Base)` |
| Issuer API models | `services/issuer/app/api/models.py` | `class <Name>(BaseModel)` |
| Verifier API models | `services/verifier/app/vvp/api_models.py` | `class <Name>(BaseModel)` |
| Common models | `common/common/vvp/models/*.py` | `@dataclass` definitions |
| Schema SAIDs | `services/issuer/app/schema/schemas/*.json` | `$id` field in each JSON |
| Environment variables | `services/issuer/app/config.py`, `services/verifier/app/core/config.py` | `os.getenv()` calls |
| Deployment config | `.github/workflows/deploy.yml` | Container App settings |
| UI pages | `services/issuer/web/*.html` | File listing |
| UI routes | `services/issuer/app/main.py:169-250` | `@app.get("/ui/...")` decorators |
