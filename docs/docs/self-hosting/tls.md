---
id: tls
title: TLS / HTTPS
---

# TLS Configuration

Always run ezone with TLS in production. The server supports TLS natively via OpenSSL.

## Generate a self-signed certificate (development only)

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=localhost"
```

## Configure TLS

```bash
EZONE_TLS_CERT=/path/to/cert.pem \
EZONE_TLS_KEY=/path/to/key.pem \
EZONE_PORT=8443 \
./ezone-server
```

## Let's Encrypt (via reverse proxy)

For production, use a reverse proxy (nginx, Caddy, Traefik) to terminate TLS and proxy to ezone:

```nginx
server {
    listen 443 ssl http2;
    server_name auth.yourapp.com;

    ssl_certificate     /etc/letsencrypt/live/auth.yourapp.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourapp.com/privkey.pem;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security headers

ezone adds the following security headers to every response automatically:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-store
Content-Security-Policy: default-src 'none'
```
