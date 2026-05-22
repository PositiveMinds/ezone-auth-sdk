# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        ca-certificates \
        libssl-dev \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DEZONE_BUILD_SERVER=ON \
        -DEZONE_POSTGRES=ON \
    && cmake --build build --target ezone-server -j"$(nproc)"

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libpq5 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN groupadd -r ezone && useradd -r -g ezone -s /sbin/nologin ezone

COPY --from=builder /src/build/rest/ezone-server /usr/local/bin/ezone-server

USER ezone
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/bin/sh", "-c", "echo > /dev/tcp/localhost/8080 2>/dev/null"]

ENTRYPOINT ["/usr/local/bin/ezone-server"]
