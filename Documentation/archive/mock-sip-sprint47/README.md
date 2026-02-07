# Mock SIP Service Archive (Sprint 47)

## Status: SUPERSEDED

These files have been archived as of Sprint 47. The monitoring dashboard
functionality has been moved to the production sip-redirect service at
`services/sip-redirect/app/monitor/`.

## Files Archived

- `mock_sip_redirect.py` - Original mock SIP signing/verification service
- `auth.py` - Session authentication module
- `monitor_web/` - Dashboard static files (HTML, CSS, JS)

## Reason for Archive

The mock service was created for testing VVP flows on the PBX. With the
production sip-redirect and sip-verify services deployed, the mock service
is redundant. The monitoring dashboard functionality was valuable and has
been integrated into the production sip-redirect service.

## Migration

The following components were migrated to `services/sip-redirect/`:

| Source | Destination |
|--------|-------------|
| `mock_sip_redirect.py` (buffer/event code) | `app/monitor/buffer.py` |
| `auth.py` | `app/monitor/auth.py` |
| `monitor_web/` | `app/monitor_web/` |

## Stopping Mock Service on PBX

To stop the mock service on the PBX VM:

```bash
az vm run-command invoke --resource-group VVP --name vvp-pbx \
  --command-id RunShellScript \
  --scripts "systemctl stop vvp-mock-sip && systemctl disable vvp-mock-sip"
```

## Date Archived

2026-02-07 (Sprint 47)
