---
id: configuration
title: Configuration
---

# Configuration

The ezone server is configured entirely through environment variables.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `EZONE_HOST` | `0.0.0.0` | Bind address |
| `EZONE_PORT` | `8080` | Listen port |
| `EZONE_THREADS` | `4` | HTTP worker threads |
| `EZONE_SESSION_TTL` | `3600` | Session token TTL in seconds (1 hour) |
| `EZONE_CHALLENGE_TTL` | `30` | Login challenge TTL in seconds |
| `EZONE_MAGIC_LINK_TTL` | `900` | Magic link TTL in seconds (15 minutes) |
| `EZONE_RECOVERY_CODES` | `8` | Number of recovery codes to generate |
| `EZONE_REVOKE_ON_RESET` | `false` | Revoke all devices on account reset |
| `EZONE_REQUIRE_FIPS` | `false` | Require OpenSSL FIPS provider |
| `EZONE_TLS_CERT` | — | Path to TLS certificate (PEM) |
| `EZONE_TLS_KEY` | — | Path to TLS private key (PEM) |

## Example production configuration

```bash
EZONE_HOST=0.0.0.0
EZONE_PORT=443
EZONE_THREADS=8
EZONE_SESSION_TTL=3600
EZONE_CHALLENGE_TTL=30
EZONE_MAGIC_LINK_TTL=900
EZONE_REVOKE_ON_RESET=true
EZONE_TLS_CERT=/etc/ssl/certs/ezone.crt
EZONE_TLS_KEY=/etc/ssl/private/ezone.key
```

## FIPS mode

To enable FIPS 140-3:

1. Install OpenSSL 3.x with the FIPS provider enabled
2. Set `EZONE_REQUIRE_FIPS=true`
3. Ensure `/etc/ssl/fips_enabled` or the platform FIPS indicator is set

If the FIPS provider is unavailable, the server will refuse to start.
