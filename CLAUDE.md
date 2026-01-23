# VVP Verifier - Claude Code Instructions

## Phase Completion Requirement

At the end of every major phase of work:

1. **Produce a summary** listing:
   - All files created or modified
   - Key changes made
   - Spec sections implemented

2. **Discuss and revise** the summary with the user

3. **Update CHANGES.md** with:
   - Phase number and title
   - Date completed
   - Files changed (with brief description)
   - Commit SHA

4. **Commit CHANGES.md** and record the commit ID in the entry

## Specification Reference

- Authoritative spec: `app/Documentation/VVP_Verifier_Specification_v1.4_FINAL.md`
- Implementation checklist: `app/Documentation/VVP_Implementation_Checklist.md`

## CI/CD

- Push to `main` triggers deployment to Azure Container Apps
- Verify deployment: `curl https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io/healthz`

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Signature Algorithm | EdDSA (Ed25519) only | VVP spec mandates, KERI ecosystem standard |
| Max PASSporT Validity | 300 seconds | Per §5.2B |
| Max iat Drift | 5 seconds | Per §5.2A (NORMATIVE) |
| SAID Algorithm | Blake3-256 | KERI ecosystem standard |
| Clock Skew | ±300 seconds | Per §4.1A |

## Project Structure

```
app/
├── core/
│   ├── __init__.py
│   └── config.py            # Configuration constants
├── vvp/
│   ├── __init__.py
│   ├── api_models.py        # Pydantic models
│   └── verify.py            # Verification stub
├── main.py                  # FastAPI application
└── Documentation/
    ├── VVP_Verifier_Specification_v1.4_FINAL.md
    └── VVP_Implementation_Checklist.md
tests/
├── __init__.py
└── test_models.py           # Phase 1 tests
```
