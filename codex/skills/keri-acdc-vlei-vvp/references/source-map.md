# Source Map — VVP Codebase

## Repository Structure

```
VVP/
├── common/vvp/                  # Shared library (pip install -e common/)
│   ├── core/                    # Logging, exceptions
│   ├── models/                  # ACDC, dossier data models
│   ├── canonical/               # KERI canonical serialization, CESR, SAID
│   ├── schema/                  # Schema registry, store, validator
│   └── utils/tn_utils.py        # Telephone number utilities
│
├── services/verifier/           # VVP Verifier (validates calls)
│   ├── app/main.py              # FastAPI app
│   ├── app/core/config.py       # TRUSTED_ROOT_AIDS, settings
│   ├── app/vvp/verify.py        # 11-phase verification pipeline
│   ├── app/vvp/header.py        # VVP-Identity header parser
│   ├── app/vvp/passport.py      # PASSporT JWT parser
│   ├── app/vvp/authorization.py # Authorization chain validation
│   ├── app/vvp/keri/            # KEL resolver, TEL client, CESR parser
│   ├── app/vvp/acdc/            # ACDC models, verifier, schema registry
│   ├── app/vvp/dossier/         # Dossier parser, validator, cache
│   └── app/vvp/vetter/          # Vetter constraint validation (Sprint 62)
│
├── services/issuer/             # VVP Issuer (manages credentials)
│   ├── app/main.py              # FastAPI app with all routers
│   ├── app/api/                 # API routers (15 router files)
│   │   ├── health.py            # Health endpoints
│   │   ├── credential.py        # Credential issue/list/revoke
│   │   ├── dossier.py           # Dossier create, build, readiness, associated
│   │   ├── organization.py      # Organization CRUD, /names
│   │   ├── tn.py                # TN mapping CRUD + lookup
│   │   ├── vvp.py               # POST /vvp/create (signing)
│   │   ├── vetter_certification.py # VetterCert CRUD (Sprint 61)
│   │   ├── admin.py             # Admin endpoints (~20)
│   │   ├── dashboard.py         # Dashboard health
│   │   └── models.py            # Pydantic request/response models
│   ├── app/keri/                # KERI identity, witness, registry, issuer
│   ├── app/vetter/              # VetterCertification service + constants (Sprint 61)
│   ├── app/dossier/             # Dossier assembly (builder)
│   ├── app/org/                 # Organization management (mock_vlei)
│   ├── app/auth/                # API keys, RBAC, sessions, OAuth
│   ├── app/db/models.py         # SQLAlchemy models (9 tables)
│   ├── app/audit/               # Audit logging
│   ├── web/                     # Multi-page web UI (19 HTML pages)
│   └── tests/                   # Test suite
│
├── services/pbx/                # PBX configuration
│   └── config/public-sip.xml    # FreeSWITCH dialplan
│
├── knowledge/                   # Deep reference docs
│   ├── architecture.md          # System architecture
│   ├── keri-primer.md           # KERI/ACDC/CESR concepts
│   ├── verification-pipeline.md # 11-phase verification flow
│   ├── schemas.md               # Schema SAIDs and governance
│   ├── api-reference.md         # All API endpoints
│   ├── data-models.md           # All Pydantic/DB models
│   ├── test-patterns.md         # Test structure and patterns
│   ├── deployment.md            # CI/CD, Azure, Docker
│   ├── dossier-parsing-algorithm.md # Dossier parsing stages
│   └── dossier-creation-guide.md # Step-by-step dossier creation
│
├── keripy/                      # Vendored KERI library
├── scripts/                     # Convenience scripts
├── SPRINTS.md                   # Sprint roadmap
├── CHANGES.md                   # Change log
└── CLAUDE.md                    # Editor instructions
```

## Key Files by Domain

### Credential Issuance
- `services/issuer/app/api/credential.py` — List/filter credentials, issue
- `services/issuer/app/api/dossier.py` — Dossier create, build, associated
- `services/issuer/app/keri/identity.py` — KERI identity management
- `services/issuer/app/keri/registry.py` — Registry management
- `services/issuer/app/keri/credential.py` — Low-level ACDC issuance

### Credential Verification
- `services/verifier/app/vvp/verify.py` — Main verification orchestrator
- `services/verifier/app/vvp/acdc/verifier.py` — ACDC chain validation
- `services/verifier/app/vvp/authorization.py` — TN rights, delegation checks
- `services/verifier/app/vvp/keri/kel_resolver.py` — KEL resolution via OOBI

### Vetter Constraints
- `services/issuer/app/vetter/service.py` — VetterCertificationManager (7-point validation)
- `services/issuer/app/vetter/constants.py` — Schema SAIDs, ECC/jurisdiction code lists
- `services/issuer/app/api/vetter_certification.py` — VetterCert CRUD API
- `services/verifier/app/vvp/vetter/constraints.py` — ECC/jurisdiction checking (Phase 11)
- `services/verifier/app/vvp/vetter/certification.py` — VetterCert credential validation
- `services/verifier/app/vvp/vetter/traversal.py` — Credential chain walk for cert backlinks

### Authentication & Authorization
- `services/issuer/app/auth/api_key.py` — API key authentication
- `services/issuer/app/auth/roles.py` — System role hierarchy
- `services/issuer/app/auth/org_roles.py` — Organization role hierarchy
- `services/issuer/app/auth/scoping.py` — Multi-tenant credential access control
- `services/issuer/app/auth/oauth.py` — Microsoft OAuth (Entra ID)

### Database Models
- `services/issuer/app/db/models.py` — 9 tables: Organization, User, UserOrgRole, OrgAPIKey, OrgAPIKeyRole, ManagedCredential, MockVLEIState, TNMapping, DossierOspAssociation

### Schema Registry
- `common/vvp/schema/registry.py` — Shared schema registry (KNOWN_SCHEMA_SAIDS)
- `services/verifier/app/vvp/acdc/schema_registry.py` — Verifier-specific registry
