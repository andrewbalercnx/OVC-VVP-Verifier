## Code Review: Sprint 27 - Local Witness Infrastructure

**Verdict:** APPROVED

### Implementation Assessment
The implementation matches the approved plan: single `kli witness demo` container, OOBI-based healthcheck, env var override in verifier config, port conflict checks in the script, and optional verifier via `--profile full`. Witness config JSON aligns with the deterministic AIDs and port mapping. Integration tests cover connectivity, OOBI responses, and config parsing.

### Code Quality
Scripts and compose definitions are clear and defensive (Docker checks, port availability, health loops). Config change is minimal and backwards-compatible. Test file is readable with explicit markers and skips by default.

### Test Coverage
Adequate for this sprint: connectivity, OOBI endpoint validation, and WitnessPool/env integration are covered, and tests are gated behind `--run-local-witnesses` to avoid CI dependence on Docker.

### Findings
- [Low]: `SPRINTS.md` exit criteria still reference `/.well-known/keri/oobi`, while the implementation and tests use `/oobi/{aid}/controller`. Consider aligning the exit criteria to the actual endpoint used in this sprint to avoid confusion. `SPRINTS.md`
- [Low]: `scripts/local-witnesses.sh` relies on `lsof` for port checks, which may be unavailable on some Linux environments; consider a fallback or note it as a dependency. `scripts/local-witnesses.sh`

### Required Changes (if not APPROVED)
1. N/A
