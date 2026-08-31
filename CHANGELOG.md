# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/), versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

### Added
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
`PostgresStorageAdapter` method round-trips correctly. The one confirmed
remaining gap: OTP's `verify` endpoint proves the code was correct but never
calls `create_session` — unlike every other method above, it cannot
currently complete a login by itself (see "Known gaps" below).

### Known gaps (not yet fixed)
- **OTP cannot complete a login.** `/auth/otp/verify` returns
  `{status, channel, code_hash}` on success but never issues a session
  token. Unlike WebAuthn/QR/push/biometric, OTP has no device-key concept,
  so it can't reuse `Auth::create_session(user_id, device_id)` without a
  design decision: either introduce a "deviceless" session (which
  `resolve_session` currently rejects outright, by design, after this
  session's device-binding fix) or auto-provision some form of identity for
  OTP-verified users. Left for a deliberate follow-up rather than a rushed
  fix.
- The rate limiter's actual reject-on-limit behavior (vs. the accept path) is
  implemented and code-reviewed but not exercised by an automated test.
- The updated CI workflow YAML was validated by running the equivalent
  commands locally, not by an actual GitHub Actions run.

### Security
- Documented and hardened the actual current threat model — see
  `docs/docs/security/threat-model.md` and `.../overview.md`, previously
  describing a pre-WebAuthn/QR/push/OTP/biometric version of the system and
  containing claims (a `jti` token nonce, "no rate limiting provided") that
  didn't match the implementation.

[Unreleased]: https://github.com/ezone-sdk/ezone-sdk/compare/v0.1.0...HEAD
