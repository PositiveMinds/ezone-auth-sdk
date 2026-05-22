---
id: fips
title: FIPS 140-3
---

# FIPS 140-3 Compliance

ezone supports FIPS 140-3 operation mode via OpenSSL 3.x's FIPS provider.

## Enabling FIPS mode

Set `EZONE_REQUIRE_FIPS=true` (or `require_fips: true` in `CryptoConfig` when embedding the C++ SDK).

When enabled, ezone calls `EVP_default_properties_enable_fips(nullptr, 1)` during initialisation. If the FIPS provider is not loaded, the server refuses to start with:

```
Fatal: FIPS mode requested but FIPS provider unavailable
```

## Algorithms approved under FIPS 140-3

All algorithms ezone uses are FIPS-approved:

| Algorithm | Standard | Use in ezone |
|---|---|---|
| AES-256-GCM | SP 800-38D | Symmetric encryption |
| ECDSA P-384 | FIPS 186-5 | Key generation, signing, verification |
| SHA-384 | FIPS 180-4 | Hashing |
| HMAC-SHA384 | FIPS 198-1 | Challenge and magic link MACs |
| DRBG (CTR-DRBG) | SP 800-90A | Random byte generation |

## Installing the OpenSSL FIPS provider

### Ubuntu 22.04+

```bash
apt-get install openssl libssl-dev
# Verify FIPS provider is available:
openssl list -providers | grep fips
```

### Building OpenSSL with FIPS

```bash
wget https://www.openssl.org/source/openssl-3.x.x.tar.gz
./Configure enable-fips
make && make install
make install_fips
```

## Verifying FIPS mode at runtime

```bash
curl http://localhost:8080/v1/health
# {"status":"ok","fips":true}
```

The `fips` field in the health response reflects the runtime FIPS status.
