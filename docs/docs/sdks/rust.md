---
id: rust
title: Rust
---

# Rust SDK

Async-first Rust client built on `reqwest` and `tokio`.

## Installation

```toml title="Cargo.toml"
[dependencies]
ezone = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick start

```rust
use ezone::{EzoneClient, BeginRegistrationRequest, CompleteLoginRequest};

#[tokio::main]
async fn main() -> ezone::Result<()> {
    let client = EzoneClient::new("https://auth.yourapp.com");

    // Registration
    let reg = client.begin_registration(BeginRegistrationRequest {
        email: "alice@example.com".into(),
    }).await?;
    println!("magic token: {}", reg.magic_token);

    // Login
    let ch = client.begin_login("alice@example.com").await?;
    // sign ch.challenge with device key...

    let session = client.complete_login(CompleteLoginRequest {
        email: "alice@example.com".into(),
        challenge: ch.challenge,
        signature: "<base64url sig>".into(),
        device_public_key: "<base64url SPKI DER>".into(),
    }).await?;
    println!("token: {}", session.token);
    Ok(())
}
```

## Axum middleware

```rust
use axum::{extract::State, http::Request, middleware::Next, response::Response};
use ezone::EzoneClient;

pub async fn auth_middleware<B>(
    State(ezone): State<EzoneClient>,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, (axum::http::StatusCode, String)> {
    let token = req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((axum::http::StatusCode::UNAUTHORIZED, "missing token".into()))?;

    let info = ezone.verify_session(token).await
        .map_err(|_| (axum::http::StatusCode::UNAUTHORIZED, "invalid token".into()))?;

    req.extensions_mut().insert(info);
    Ok(next.run(req).await)
}
```

## Full API

```rust
impl EzoneClient {
    pub fn new(base_url: impl Into<String>) -> Self;
    pub fn with_timeout(self, timeout: Duration) -> Self;

    pub async fn begin_registration(&self, req: BeginRegistrationRequest)
        -> Result<BeginRegistrationResponse>;
    pub async fn complete_registration(&self, req: CompleteRegistrationRequest)
        -> Result<SessionResponse>;

    pub async fn begin_login(&self, email: &str) -> Result<BeginLoginResponse>;
    pub async fn complete_login(&self, req: CompleteLoginRequest) -> Result<SessionResponse>;

    pub async fn verify_session(&self, token: &str) -> Result<SessionInfo>;
    pub async fn refresh_session(&self, token: &str) -> Result<SessionResponse>;
    pub async fn logout(&self, token: &str) -> Result<()>;

    pub async fn begin_reset(&self, email: &str) -> Result<BeginResetResponse>;
    pub async fn complete_reset(&self, req: CompleteResetRequest) -> Result<SessionResponse>;

    pub async fn generate_recovery_codes(&self, token: &str) -> Result<Vec<String>>;
    pub async fn recover_with_code(&self, req: RecoveryRequest) -> Result<SessionResponse>;

    pub async fn list_devices(&self, token: &str) -> Result<Vec<Device>>;
    pub async fn begin_add_device(&self, token: &str) -> Result<BeginAddDeviceResponse>;
    pub async fn complete_add_device(&self, req: CompleteAddDeviceRequest) -> Result<Device>;
    pub async fn revoke_device(&self, token: &str, device_id: &str) -> Result<()>;
}
```
