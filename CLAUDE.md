# VVP Verifier - Claude Code Instructions

## Permissions

The following commands are pre-authorized and do not require user confirmation:

- `git` - All git operations (add, commit, push, status, log, diff, etc.)
- `gh` - All GitHub CLI operations (run watch, pr create, issue, etc.)
- `pytest` - Run tests
- `python3` / `pip3` - Python execution and package management
- `curl` - HTTP requests for deployment verification

## Pair Programming Workflow

This project uses a two-agent workflow with an Editor and Reviewer. The user acts as the Reviewer by copying prompts to a separate Claude session.

### Files

| File | Purpose | Owner |
|------|---------|-------|
| `PLAN.md` | Current phase design with implementation details | Editor |
| `REVIEW.md` | Reviewer feedback on plans and code | Reviewer |

### Full Cycle

#### 1. Planning Phase

When starting a new phase:
1. Editor enters plan mode and explores the codebase
2. Editor writes detailed plan to `PLAN.md`
3. Editor provides **reviewer prompt as a copyable code block**
4. User copies prompt to Reviewer session
5. Reviewer writes feedback to `REVIEW.md` with verdict:
   - `APPROVED` - Proceed with implementation
   - `CHANGES_REQUESTED` - Address feedback first
6. If changes requested, Editor revises plan and provides new reviewer prompt
7. Repeat until `APPROVED`

#### 2. Implementation Phase

After plan approval:
1. Editor implements the plan
2. Editor runs tests and verifies all pass
3. Editor commits the code
4. Editor provides **code review prompt as a copyable code block**

#### 3. Code Review Phase

1. User copies code review prompt to Reviewer session
2. Reviewer examines all modified files
3. Reviewer writes feedback to `REVIEW.md` with verdict:
   - `APPROVED` - Phase complete
   - `CHANGES_REQUESTED` - Fix issues first
4. If changes requested:
   - Editor fixes issues
   - Editor provides new review prompt
   - Repeat until `APPROVED`

### Reviewer Prompt Format

Always provide prompts as copyable code blocks:

```
## Review Request: Phase N - Title

### Context
Brief description of what was implemented.

### Spec References
- §X.Y: Section name

### Files to Review
- `path/to/file.py` (action: created/modified)
- ...

### Verification
```bash
# Commands to verify the implementation
python3 -m pytest tests/test_xxx.py -v
```

### Key Design Decisions
1. Decision 1 and rationale
2. Decision 2 and rationale

### Open Questions
1. Question for reviewer to consider
2. Another question

### Test Results
N passed
```

### Reviewer Response Format

Reviewer writes to `REVIEW.md`:

```markdown
## Review: Phase N - Title

**Verdict:** APPROVED | CHANGES_REQUESTED

### Findings
- [High]: Critical issue that must be fixed
- [Medium]: Important issue that should be fixed
- [Low]: Minor suggestion (optional)

### Answers to Open Questions
1. Answer to question 1
2. Answer to question 2

### Additional Recommendations
- Any other suggestions
```

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

### Normative (fixed by spec)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Signature Algorithm | EdDSA (Ed25519) only | §5.0, §5.1 - VVP mandates |
| Max iat Drift | 5 seconds | §5.2A - "MUST be ≤ 5 seconds" |
| SAID Algorithm | Blake3-256 | KERI ecosystem standard |

### Configurable Defaults

| Decision | Default | Rationale |
|----------|---------|-----------|
| Max PASSporT Validity | 300 seconds | §5.2B - "unless explicitly configured otherwise" |
| Clock Skew | ±300 seconds | §4.1A - "default policy" |
| Max Token Age | 300 seconds | §5.2B - configurable |

## Vendored Dependencies

- **keripy/** - KERI Python library (vendored, not yet integrated)
  - Excluded from pytest discovery via `pytest.ini`
  - TODO: Record upstream commit/version for reproducibility

## Project Structure

```
app/
├── core/
│   ├── __init__.py
│   └── config.py            # Configuration constants
├── vvp/
│   ├── __init__.py
│   ├── api_models.py        # Pydantic models (Phase 1)
│   ├── exceptions.py        # VVPIdentityError, PassportError (Phase 2-3)
│   ├── header.py            # VVP-Identity parser (Phase 2)
│   ├── passport.py          # PASSporT JWT parser (Phase 3)
│   ├── verify.py            # Verification stub (Phase 6+)
│   └── keri/                # KERI integration (Phase 4)
│       ├── __init__.py
│       ├── exceptions.py    # KeriError, SignatureInvalidError
│       ├── key_parser.py    # parse_kid_to_verkey
│       └── signature.py     # verify_passport_signature
├── main.py                  # FastAPI application
└── Documentation/
    ├── VVP_Verifier_Specification_v1.4_FINAL.md
    └── VVP_Implementation_Checklist.md
tests/
├── __init__.py
├── test_models.py           # Phase 1 tests
├── test_header.py           # Phase 2 tests
├── test_passport.py         # Phase 3 tests
└── test_signature.py        # Phase 4 tests
```
