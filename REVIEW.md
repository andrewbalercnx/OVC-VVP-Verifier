## Code Review: Sprint 50 - SIP Monitor Multi-Auth

**Verdict:** APPROVED

### Implementation Assessment
The implementation matches the plan: OAuth (PKCE + state/nonce), API key login, and password auth are wired into the aiohttp monitor with session `auth_method` tracking. Config additions and login UI changes align with the expected flow, and OAuth state handling uses Lax cookies while session cookies remain Strict.

### Code Quality
Code is clean and consistent with existing patterns. Error handling is explicit in OAuth exchange/validation and login flows, and the API key store reload logic is straightforward.

### Test Coverage
Unit coverage is good for OAuth state/PKCE/domain helpers and API key store/session auth_method behavior. Endpoint-level tests (server handlers for OAuth/login) are not present but the core logic is exercised.

### Findings
- [Low]: OAuth state cookie `max_age` is hard-coded to 600 seconds in `handle_oauth_start` instead of using `MONITOR_OAUTH_STATE_TTL`. Consider aligning the cookie TTL with the configured state store TTL for consistency. (`services/sip-redirect/app/monitor/server.py`)

### Required Changes (if not APPROVED)
N/A

### Plan Revisions (if PLAN_REVISION_REQUIRED)
N/A
