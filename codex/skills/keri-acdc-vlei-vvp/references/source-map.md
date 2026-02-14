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
│   └── app/vvp/dossier/         # Dossier parser, validator, cache
│
├── services/issuer/             # VVP Issuer (manages credentials)
│   ├── app/main.py              # FastAPI app with all routers
│   ├── app/api/                 # API routers
│   │   ├── health.py            # Health endpoints
│   │   ├── credential.py        # GET /credential (list, filter)
│   │   ├── dossier.py           # POST /create, GET /associated, build
│   │   ├── organization.py      # GET /names, org management
│   │   ├── tn_mapping.py        # TN mapping CRUD
│   │   ├── vvp.py               # POST /api/vvp/create (signing)
│   │   └── models.py            # Pydantic request/response models
│   ├── app/keri/                # KERI identity, witness, registry
│   ├── app/auth/                # API keys, RBAC, sessions
│   ├── app/db/models.py         # SQLAlchemy models (Organization, ManagedCredential, etc.)
│   ├── app/audit/               # Audit logging
│   ├── web/                     # Multi-page web UI
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
│   └── test-patterns.md         # Test structure and patterns
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

### Authentication & Authorization
- `services/issuer/app/auth/api_key.py` — API key authentication
- `services/issuer/app/auth/rbac.py` — Role-based access control
- `services/issuer/app/api/scoping.py` — Credential access scoping

### Database Models
- `services/issuer/app/db/models.py` — Organization, ManagedCredential, TNMapping, DossierOspAssociation, etc.

### Schema Registry
- `common/vvp/schema/registry.py` — Shared schema registry
- `services/verifier/app/vvp/acdc/schema_registry.py` — Verifier-specific registry
