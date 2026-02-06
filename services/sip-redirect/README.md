# VVP SIP Redirect Service

Sprint 42: SIP redirect signing service for VVP attestation.

## Overview

This service receives SIP INVITE requests from enterprise PBXs/SBCs, authenticates them via X-VVP-API-Key header, looks up TN mappings from the issuer service, creates VVP-Identity headers and PASSporTs, and returns 302 redirect responses with the attestation headers.

## Architecture

```
Enterprise SBC ──SIP INVITE──> SIP Redirect Service ──HTTPS──> Issuer API
     ^              (5060/5061)      │                         │
     │                              │  POST /tn/lookup        │
     │                              │  POST /vvp/create       │
     │                              │                         ▼
     └───SIP 302 + VVP headers──────┘              Database (TN Mappings)
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VVP_SIP_LISTEN_HOST` | `0.0.0.0` | Listen address |
| `VVP_SIP_LISTEN_PORT` | `5060` | SIP UDP/TCP port |
| `VVP_SIP_TRANSPORT` | `udp` | Transport (udp, tcp, both, all) |
| `VVP_SIPS_ENABLED` | `false` | Enable SIPS (TLS) on 5061 |
| `VVP_SIPS_LISTEN_PORT` | `5061` | SIPS TLS port |
| `VVP_SIPS_CERT_FILE` | - | Path to TLS certificate |
| `VVP_SIPS_KEY_FILE` | - | Path to TLS private key |
| `VVP_ISSUER_URL` | `http://localhost:8001` | Issuer API URL |
| `VVP_ISSUER_TIMEOUT` | `10.0` | API timeout (seconds) |
| `VVP_RATE_LIMIT_RPS` | `10.0` | Requests per second per API key |
| `VVP_RATE_LIMIT_BURST` | `50` | Burst size for rate limiter |
| `LOG_LEVEL` | `INFO` | Logging level |

## Running

```bash
# Install
pip install -e .

# Run
python -m app.main
```

## Testing

```bash
pytest tests/ -v
```
