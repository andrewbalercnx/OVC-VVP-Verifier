## Code Review: Sprint 41 - Org Role Access Resolution

**Verdict:** APPROVED

### Previous Finding Resolution
Yes. Credential/dossier endpoints now use `require_auth` plus explicit combined role checks, so org-only principals can access these APIs while still being constrained by org scoping. This resolves the prior [High] finding.

### Implementation Assessment
The combined system/org role helpers in `roles.py` are clear and consistent with existing patterns. Endpoints call `check_credential_access_role` / `check_credential_write_role` / `check_credential_admin_role` appropriately, and existing scoping (`can_access_credential`, `validate_dossier_chain_access`) continues to enforce tenant isolation. Changes are targeted and easy to follow.

### Security Review
No new isolation gaps observed. Access is granted by role, while resource-level checks still enforce org ownership. Full-chain dossier validation remains in place. The only policy consideration is whether org:dossier_manager should be allowed to issue credentials (now possible via `check_credential_write_role`). If issuance should be system-only, tighten that check.

### Test Coverage
New tests cover combined role checks and org role hierarchy, and existing multi-tenant tests already validate scoping. Coverage is adequate for the new authorization functions; endpoint-level role behavior is indirectly covered by these checks.

### Findings
- [Low]: Confirm whether `org:dossier_manager` should be allowed to issue credentials. If not, restrict `check_credential_write_role` for `/credential/issue` to system operator+ or org:administrator.

### Required Changes (if not APPROVED)
1. N/A
