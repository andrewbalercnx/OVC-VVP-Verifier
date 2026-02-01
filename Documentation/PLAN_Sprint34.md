# Sprint 34: Schema Management

## Goal
Import schemas from WebOfTrust/schema repository, add SAID generation capability, and enhance schema management UI.

## Background

The [WebOfTrust/schema repository](https://github.com/WebOfTrust/schema/tree/main) provides:
- **registry.json** - Schema registry listing all available schemas with metadata
- **kaslcred/** - Tool for creating JSON Schema ACDCs with proper SAID computation
- **vLEI schemas** - Legal Entity, QVI, OOR, ECR credentials used by GLEIF

Currently our issuer embeds schemas as pre-loaded JSON files with hard-coded SAIDs. This sprint adds:
1. Import schemas from WebOfTrust repository
2. Compute SAIDs for new/modified schemas
3. UI for schema management (view, create, validate)

## Proposed Solution

### Approach
Extend the schema subsystem with three new capabilities:
1. **Schema Import** - Fetch and validate schemas from WebOfTrust repository
2. **SAID Generation** - Compute SAIDs for new schemas using KERI canonical form
3. **Schema Management UI** - Enhanced interface for viewing, importing, and creating schemas

### Key Design Decisions

1. **SAID Computation**: Use keripy's `Saider.saidify()` directly - battle-tested, handles all edge cases
2. **Version Pinning**: Support commit SHA/tag via `VVP_SCHEMA_REPO_REF` environment variable
3. **Storage Separation**: Embedded (read-only) vs user-added (writable) schemas
4. **Metadata Handling**: Store `_source` metadata separately, strip before SAID verification

## Files Created/Modified

| File | Action | Purpose |
|------|--------|---------|
| `services/issuer/app/schema/said.py` | Created | SAID computation module |
| `services/issuer/app/schema/importer.py` | Created | Schema import service |
| `services/issuer/app/schema/store.py` | Modified | Add write capability, metadata stripping |
| `services/issuer/app/schema/__init__.py` | Created | Module exports |
| `services/issuer/app/api/schema.py` | Modified | Add import/create/delete/verify endpoints |
| `services/issuer/app/api/models.py` | Modified | Add request/response models |
| `services/issuer/web/schemas.html` | Modified | Enhanced UI with tabs |
| `services/issuer/tests/test_said.py` | Created | SAID computation tests (19 tests) |
| `services/issuer/tests/test_import.py` | Created | Import service tests (14 tests) |
| `services/issuer/tests/test_schema.py` | Modified | Added metadata/verification tests (3 tests) |
| `SPRINTS.md` | Modified | Added Sprint 34 definition |

## Exit Criteria - All Met

- [x] SAID computation produces correct SAIDs for all vLEI schemas
- [x] Import from WebOfTrust registry works end-to-end
- [x] Create new schema with auto-SAID works
- [x] UI shows schema source (embedded/imported/custom)
- [x] Delete works only for user-added schemas
- [x] All tests passing (47 passed, 1 skipped)

---

## Implementation Notes

### Code Review Iterations

**Round 1 - CHANGES_REQUESTED:**
- [Medium] `_source` metadata injected into stored schemas broke SAID verification
- [Low] Comment in `fetch_schema_by_path()` didn't match behavior

**Round 2 - APPROVED:**
- Added `_strip_metadata()` function to remove internal fields before verification
- Modified `get_schema()` to strip metadata by default
- Fixed misleading comment in importer
- Added tests for metadata stripping behavior

### Test Results
```
tests/test_schema.py - 13 passed
tests/test_said.py - 19 passed
tests/test_import.py - 14 passed, 1 skipped
Total: 47 passed, 1 skipped
```

### API Endpoints Added
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/schema/weboftrust/registry` | GET | readonly | List schemas in WebOfTrust registry |
| `/schema/import` | POST | admin | Import schema from URL or WebOfTrust |
| `/schema/create` | POST | admin | Create new schema with SAID |
| `/schema/{said}` | DELETE | admin | Remove user-added schema |
| `/schema/{said}/verify` | GET | readonly | Verify schema SAID |

### Review History
- Plan Review 1: CHANGES_REQUESTED - SAID algorithm underspecified, path mismatch
- Plan Review 2: APPROVED
- Code Review 1: CHANGES_REQUESTED - _source metadata issue
- Code Review 2: APPROVED
