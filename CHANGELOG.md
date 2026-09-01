# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/), versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

### Fixed (found by actually running the pushed CI, not just locally)
Pushing the previous two commits' worth of work was the first time this
branch's CI had actually run end-to-end. It failed on nearly every job —
closing that gap surfaced real, previously-invisible bugs:
- **`write_u32_be` (auth.cpp) was defined but never called** — GCC/Clang
  both fail the build on this under `-Werror -Wunused-function`; MSVC's
  `/W4` doesn't flag it the same way, so it was invisible locally. Removed
  (genuinely dead code, not used anywhere).
- **`sodium_init()`'s return value was silently discarded.** It's marked
  `warn_unused_result` for a real reason — a `-1` return means libsodium's
  RNG/implementation selection didn't complete, and every crypto primitive
  called afterward would run without the guarantees libsodium is supposed to
  provide. Now aborts at startup on failure instead of silently continuing
  on broken crypto. Also only ever compiled on Linux (the new CI leg) since
  it's the `EZONE_USE_LIBSODIUM=ON` path — GCC's `-Werror=unused-result`
  caught what no prior build ever exercised.
- **`docker-compose.yml`/`render.yaml` never surfaced the new
  `EZONE_HMAC_KEY`/`EZONE_TOKEN_PRIVATE_KEY`/`EZONE_TOKEN_PUBLIC_KEY`/
  `EZONE_ENABLED_METHODS`/`EZONE_WEBAUTHN_RP_ID` env vars** — both "one-click
  deploy" paths this repo advertises would have silently kept the
  fresh-keys-every-restart behavior the key-persistence fix was meant to
  close. Added to both, along with a `getenv_nonempty()` helper in
  `main.cpp`: these compose/Render templates pass optional vars through as
  `"${VAR:-}"`, which sets the container's env var to an *empty string*
  when the host doesn't provide one — plain `std::getenv() != nullptr`
  treats that as "provided," which would have silently overwritten
  defaults like `webauthn_rp_id`'s `"localhost"` with `""`.
- **`bindings/go`'s `BearerMiddleware`/`SessionFromContext` never actually
  worked.** Each declared its own function-local `type ctxKey struct{}` —
  in Go, locally-scoped type declarations are distinct types even with an
  identical name, so `ctx.Value(ctxKey{})` in `SessionFromContext` could
  never match what `BearerMiddleware` stored under *its own* `ctxKey`
  type. `ok` was always `false`. Fixed by hoisting a single shared
  `sessionCtxKey` type. The Go test suite's mock server was also missing a
  route for `DELETE /v1/auth/devices/{id}` entirely (only registered
  `/v1/auth/devices` with no ID segment) — `TestMultiDevice` and
  `TestBearerMiddleware` had never actually passed.
- **`docs/` (the Docusaurus site) had no committed lockfile** (same class
  of bug already fixed for `bindings/nodejs`/`bindings/browser` — `npm ci`
  had nothing to install from) **and didn't build even once regenerated** —
  Docusaurus 3.5.2's bundled `webpackbar` passes options to webpack's
  `ProgressPlugin` that a newer resolved webpack (5.110.2, with no lockfile
  previously pinning it) rejects as schema-invalid. Bumped to Docusaurus
  3.10.2, which resolves a compatible webpack internally; build now
  succeeds.
- **The macOS C++ job failed at the link step for every test binary**:
  `ld: unknown options: -z -z`. `-Wl,-z,relro -Wl,-z,now` (RELRO/BIND_NOW
  hardening) is GNU-ld/glibc-specific syntax Apple's `ld64` doesn't
  understand, but it was being applied to every non-MSVC build, Linux and
  macOS alike — same issue for the `-D_FORTIFY_SOURCE=2` compile macro.
  Both now gated to Linux only.
- **Every Python SDK CI job (3.9/3.11/3.12) failed to build a wheel**:
  `bindings/python/pyproject.toml` declared
  `build-backend = "setuptools.backends.legacy:build"`, which is not an
  importable module in any current setuptools release. Corrected to the
  real PEP 517 backend, `setuptools.build_meta`.

With all of the above, this repository's full CI matrix (C++ on
Linux/macOS/Windows, with and without Libsodium; Node.js; Browser; Python
3.9/3.11/3.12; Go 1.22/1.23; Docs) passes end-to-end for the first time.

### Added
- `getenv_nonempty()` in `rest/main.cpp` — every optional env var the server
  reads now treats an empty string the same as unset, matching how
  `docker-compose.yml`/`render.yaml` pass optional values through.
- `EZONE_HMAC_KEY` / `EZONE_TOKEN_PRIVATE_KEY` / `EZONE_TOKEN_PUBLIC_KEY` —
  load a persisted, stable server key set instead of generating fresh random
  keys on every start. This was a hard production blocker: without it, every
  restart invalidated every session/magic link/recovery code, and running
  more than one instance was broken outright (each generates independent
  keys, so a token from instance A never verifies on instance B). With none
  of the three set, the server still generates fresh keys for convenience
  (dev/test only) but now prints them once so they can be captured; setting
  only some of the three is rejected at startup rather than silently
  falling back. Verified with a real two-instance test: a magic token
  issued by one running instance was accepted by a separately-started
  instance loading the same captured keys, and rejected by a third instance
  started with different (freshly-generated) keys.
- WebAuthn/FIDO2, QR-code cross-device login, push notification approval,
  OTP (email/SMS), and biometric-provider auth methods alongside the original
  challenge-response, magic-link, and recovery-code flows.
- `CryptoStrategy`: automatic algorithm selection (P-384/Ed25519,
  AES-256-GCM/ChaCha20-Poly1305, PBKDF2/Argon2id) based on platform
  capabilities and FIPS requirements, with an optional Libsodium backend.
- Full REST endpoints for every auth method, including biometric login
  (previously implemented in the SDK but never exposed over HTTP).
- `EZONE_ENABLED_METHODS` and `EZONE_WEBAUTHN_RP_ID`/`EZONE_WEBAUTHN_RP_NAME`
  environment variables — without these, the shipped `ezone-server` binary
  could only ever run with the default 3 methods, and WebAuthn could never
  work against a real domain.
- `EZONE_TRUST_PROXY` — `X-Forwarded-For` is only trusted for client IP
  (rate limiting, QR IP-binding) when this is explicitly enabled.
- Rate limiting now applies to every `/auth/*` endpoint, including
  status-polling, listing, and delete routes that previously had none.
- `Auth::create_session()` — issues a real session token for auth methods
  (WebAuthn, QR, push, biometric) that verify identity independently of the
  challenge-response flow.
- `CryptoEngine::derive_device_id()` — public, consistent device-ID
  derivation for callers (e.g. biometric login) that only learn a signer's
  identity after verifying a signature.
- CI now builds the REST server (`EZONE_BUILD_SERVER=ON`) and the
  Libsodium-enabled path (`EZONE_USE_LIBSODIUM=ON`, Linux) — previously CI
  built neither, so neither had ever been compiled before this release.

### Fixed
- **The project did not compile.** Numerous typos, type errors, and
  mismatched signatures across the newly-added auth methods left the SDK,
  the REST server, and the test suite all unbuildable. Highlights:
  - `namespace` typo in `auth.h`; type-confusion bugs in `qr_auth.cpp`
    (`Result<T>` vs. its unwrapped value) that made QR login uncompilable.
  - `CryptoEngine`'s Libsodium-backed methods were declared only inside
    `#ifdef EZONE_LIBSODIUM_ENABLED` in the header, but called
    unconditionally elsewhere via a runtime `has_libsodium()` check —
    unbuildable without Libsodium, defeating the point of a runtime-selectable
    crypto strategy. Declarations are now unconditional; the `.cpp` already
    had matching real/stub implementations.
  - A broken base64 decode lookup-table construction (invalid `std::array`
    conversion) and a `PostgresStorageAdapter` left out of sync with a
    `StorageAdapter` interface change (missing ~10 overrides).
  - `Result<Auth>::failure()` required `Auth` to be default-constructible,
    which it deliberately wasn't — fixed via a private constructor and
    friend declaration, not a public API change.
  - **The entire `EZONE_USE_LIBSODIUM=ON` path had never been compiled by
    anyone, ever** (no CI coverage): `x25519_exchange` called the wrong
    libsodium primitive (a 5-argument client/server handshake function,
    with 4 arguments and wrong semantics) instead of plain
    `crypto_scalarmult`; `argon2id_derive` referenced `crypto_pwhash_BYTES`,
    which does not exist in libsodium; `CryptoEngine::sodium_memcmp`/
    `sodium_memzero` called themselves recursively instead of libsodium's
    functions, because `#include <sodium.h>` was placed *inside*
    `namespace ezone`, silently pulling libsodium's C API into `ezone::` and
    shadowing the identically-named wrapper methods. All four now build,
    link, and were functionally verified (Ed25519 sign/verify, X25519
    shared-secret agreement, ChaCha20-Poly1305 round-trip + AAD
    authentication, deterministic Argon2id derivation).
- **Account activation**: `complete_registration` never actually persisted
  `active = true` — every newly-registered account was permanently locked
  out on first login.
- **Device binding**: session tokens didn't embed which device issued them;
  `resolve_session`/`logout` picked "the first active device" on the
  account, so on multi-device accounts a token from one device could revoke
  or report on a different one. Tokens now embed `device_id`.
- **QR login could be hijacked**: `/auth/qr/approve` accepted an
  unregistered, attacker-supplied keypair with no check that it belonged to
  a real account device. Now validated against a pre-registered
  `DeviceRecord` before approval succeeds.
- **OTP lockout never actually triggered**: `is_locked()` treated "failures
  recorded but threshold not yet crossed" (`locked_until == 0`) the same as
  "lockout expired," silently erasing the failed-attempt counter on every
  check — so the documented 3-attempts-then-lockout brute-force protection
  never engaged.
- **`X-Forwarded-For` spoofing**: the client-IP helper trusted this header
  unconditionally, letting any client bypass rate limiting and QR IP-binding.
- **FIPS enforcement was unreachable**: `EZONE_REQUIRE_FIPS`
  (`AuthConfig::crypto_strategy.require_fips`) never propagated to
  `CryptoEngine`'s actual startup enforcement check — it only affected
  algorithm *selection*. Sessions also always used a hardcoded 1-hour token
  TTL regardless of `EZONE_SESSION_TTL`/`AuthConfig::session_ttl_seconds`,
  for the same reason (a config field constructed but never wired through).
- `/health` hardcoded `"fips":false` regardless of actual FIPS status.
- Rate limiter had no bucket eviction — every distinct source IP (or
  spoofed `X-Forwarded-For` value) left a permanent entry, an unbounded
  memory-growth DoS vector over time.
- `resend_provider.cpp` (linked into the `ezone-sdk` library whenever the
  server is built) had no include path to `httplib.h` at all in CMake.

### Fixed (found via genuine end-to-end testing, not code review)
- **WebAuthn registration could never succeed, for any input, real or
  fake.** `parse_cose_key`'s field loop discarded every negative-integer CBOR
  key before ever inspecting it (`if (!is_uint()) continue;`) — but COSE_Key
  labels for `x`/`y`/`crv` are all negative integers per RFC 8152. The
  function could not have extracted a public key from any attestation object,
  ever. It also read `-1`/`-2` as `x`/`y` with no `crv` field at all, instead
  of the real COSE EC2 layout (`-1`=crv, `-2`=x, `-3`=y) — so even after
  fixing the lookup, it would still have silently failed against every real
  authenticator (browsers use the correct labels).
- **Every WebAuthn credential was stored with an empty `user_id`.**
  `register/complete` read a `token` field from the request body and never
  verified it, then built a fresh `WebAuthnRegistrationOptions` with `user_id`
  left at its default (empty string) before storing the resulting credential
  — disconnecting it from any account and colliding with every other user's
  credentials under that same empty key. `authenticate/begin`'s credential
  lookup (keyed by the real user_id) could therefore never find anything.
  Fixed by requiring and verifying a bearer session, and storing the
  credential under that session's real user_id.
- **`PostgresStorageAdapter::create_user` silently ignored the `active`
  field** — the INSERT never listed the `active` column, so every new user
  got the schema's `DEFAULT TRUE` regardless of what the caller passed. On a
  Postgres deployment this would have bypassed the "inactive until
  magic-link confirmation" property entirely (verified against a live
  PostgreSQL 18.4 instance, not assumed).
- CMake's Libsodium detection now also searches for `libsodium.lib` on
  Windows (previously only `sodium.lib`, which prebuilt MSVC packages don't
  produce), and defines `SODIUM_STATIC` under MSVC so the static-lib case
  links correctly.

Verified with real, end-to-end tests — not just unit tests against the SDK
directly, but genuine HTTP round-trips against a live `ezone-server` with
real ECDSA signatures, a real CBOR/COSE-encoded WebAuthn attestation object
built to the actual spec, and a real PostgreSQL 18.4 instance: QR, biometric,
push, and WebAuthn logins all complete and issue real session tokens;
attacker/unregistered-key/replay attempts are all rejected; every
`PostgresStorageAdapter` method round-trips correctly.

- **OTP now completes a login, not just a verification.** `/auth/otp/verify`
  previously returned `{status, channel, code_hash}` on success but never
  issued a session — unlike every other method above. OTP has no
  device-key concept to reuse `Auth::create_session(user_id, device_id)`
  with directly, so this binds to a stable synthetic "OTP device" derived
  from the user_id (via `CryptoEngine::derive_device_id`, repurposed as a
  generic stable-ID hash rather than strictly a public-key hash), created
  on first use. Only issued when the identifier matches an existing active
  account with a known email — an unmatched identifier still gets a plain
  `200` with no token field, so this can't be used to probe account
  existence. Verified end-to-end: an existing account's OTP now returns a
  working session token that resolves to the right account; a
  non-existent account's OTP still verifies (no error) but issues no token.

### Removed
- **The `/auth/otp/sms` REST endpoint.** With no SMS gateway wired by
  default (`OTPServer::set_sms_sender` is never called unless an embedder
  does it themselves), it would still generate and hash a real code and
  consume rate-limit budget, just never deliver it anywhere — and even when
  "verified," it could never complete a login regardless, since
  `StorageAdapter` has no phone-indexed user lookup for the session-issuance
  fix above to use. `OTPServer::request_sms()` is unchanged and still usable
  by anyone embedding the C++ SDK directly with their own gateway wired up;
  only the exposed-by-default REST surface was removed.

### Known gaps (not yet fixed)
- The rate limiter's actual reject-on-limit behavior (vs. the accept path) is
  implemented and code-reviewed but not exercised by an automated test.

### Security
- Documented and hardened the actual current threat model — see
  `docs/docs/security/threat-model.md` and `.../overview.md`, previously
  describing a pre-WebAuthn/QR/push/OTP/biometric version of the system and
  containing claims (a `jti` token nonce, "no rate limiting provided") that
  didn't match the implementation.

[Unreleased]: https://github.com/ezone-sdk/ezone-sdk/compare/v0.1.0...HEAD
