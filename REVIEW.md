Code Review: Phase 9.3 + Admin - Revocation Integration (Revision 2)
Verdict: APPROVED

Implementation Assessment
The dossier status now correctly propagates from `revocation_clear`, and revoked credentials emit `CREDENTIAL_REVOKED` errors. The claim tree matches §3.3B and the revocation semantics are unambiguous.

Code Quality
Changes are localized and consistent with existing patterns. Error emission uses the existing `ErrorDetail`/`ERROR_RECOVERABILITY` structure and maintains clarity.

Test Coverage
New tests cover dossier status propagation and revoked SAID collection for error emission. Existing revocation and admin tests still cover the core paths.

Findings
[Low]: Admin endpoint env leakage note remains; not addressed in this revision but also not required for approval.
