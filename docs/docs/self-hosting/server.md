---
id: server
title: Running the Server
---

# Running the ezone Server

## Docker (recommended)

```bash
docker run -d \
  --name ezone-server \
  -p 8080:8080 \
  -e EZONE_SESSION_TTL=3600 \
  -e EZONE_CHALLENGE_TTL=30 \
  -e EZONE_THREADS=4 \
  ghcr.io/ezone-sdk/ezone-server:latest
```

## Binary

Download a pre-built binary for your platform from the [GitHub Releases](https://github.com/ezone-sdk/ezone-sdk/releases) page, then:

```bash
EZONE_PORT=8080 ./ezone-server
```

## Build from source

```bash
git clone https://github.com/ezone-sdk/ezone-sdk
cd ezone-sdk

cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DEZONE_BUILD_SERVER=ON \
  -DBUILD_SHARED_LIBS=ON

cmake --build build --config Release
./build/ezone-server
```

## Health check

```bash
curl http://localhost:8080/v1/health
# {"status":"ok","fips":false}
```

## Next steps

- [Configuration](/docs/self-hosting/configuration) — environment variables and tuning
- [TLS](/docs/self-hosting/tls) — enable HTTPS in production
