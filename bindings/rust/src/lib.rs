use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, EzoneError>;

#[derive(Debug, Error)]
pub enum EzoneError {
    #[error("HTTP error {status}: {message}")]
    Api { status: u16, message: String },
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
}

// ── Request types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BeginRegistrationRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct CompleteRegistrationRequest {
    pub magic_token:      String,
    pub device_public_key: String,
    pub device_name:      String,
}

#[derive(Debug, Serialize)]
pub struct BeginLoginRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct CompleteLoginRequest {
    pub email:             String,
    pub challenge:         String,
    pub signature:         String,
    pub device_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct CompleteResetRequest {
    pub magic_token:      String,
    pub device_public_key: String,
    pub device_name:      String,
}

#[derive(Debug, Serialize)]
pub struct RecoveryRequest {
    pub email:             String,
    pub code:              String,
    pub device_public_key: String,
    pub device_name:       String,
}

#[derive(Debug, Serialize)]
pub struct CompleteAddDeviceRequest {
    pub magic_token:      String,
    pub device_public_key: String,
    pub device_name:      String,
}

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BeginRegistrationResponse {
    pub magic_token: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionResponse {
    pub token:      String,
    pub expires_at: i64,
    pub user_id:    Option<String>,
    pub device_id:  Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BeginLoginResponse {
    pub challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionInfo {
    pub user_id:    String,
    pub email:      String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct Device {
    pub device_id:      String,
    pub device_name:    String,
    pub registered_at:  i64,
}

#[derive(Debug, Deserialize)]
pub struct DevicesResponse {
    pub devices: Vec<Device>,
}

#[derive(Debug, Deserialize)]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

// ── Client ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct EzoneClient {
    base_url: String,
    client:   Client,
}

impl EzoneClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_timeout(base_url, Duration::from_secs(10))
    }

    pub fn with_timeout(base_url: impl Into<String>, timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .expect("failed to build reqwest client");
        Self { base_url: base_url.into(), client }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1{}", self.base_url.trim_end_matches('/'), path)
    }

    async fn post<B: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
        token: Option<&str>,
    ) -> Result<R> {
        let mut req = self.client.post(self.url(path)).json(body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await?;
        self.parse(resp).await
    }

    async fn get<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        token: &str,
    ) -> Result<R> {
        let resp = self.client.get(self.url(path)).bearer_auth(token).send().await?;
        self.parse(resp).await
    }

    async fn delete(&self, path: &str, token: &str) -> Result<()> {
        let resp = self.client.delete(self.url(path)).bearer_auth(token).send().await?;
        if resp.status().is_success() { Ok(()) } else {
            let status = resp.status().as_u16();
            let msg = resp.json::<ErrorResponse>().await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unknown error".into());
            Err(EzoneError::Api { status, message: msg })
        }
    }

    async fn parse<R: for<'de> Deserialize<'de>>(&self, resp: reqwest::Response) -> Result<R> {
        if resp.status().is_success() {
            Ok(resp.json::<R>().await?)
        } else {
            let status = resp.status().as_u16();
            let msg = resp.json::<ErrorResponse>().await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unknown error".into());
            Err(EzoneError::Api { status, message: msg })
        }
    }

    // ── Registration ────────────────────────────────────────────────────────

    pub async fn begin_registration(&self, req: BeginRegistrationRequest)
        -> Result<BeginRegistrationResponse>
    {
        self.post("/auth/register/begin", &req, None).await
    }

    pub async fn complete_registration(&self, req: CompleteRegistrationRequest)
        -> Result<SessionResponse>
    {
        self.post("/auth/register/complete", &req, None).await
    }

    // ── Login ───────────────────────────────────────────────────────────────

    pub async fn begin_login(&self, email: &str) -> Result<BeginLoginResponse> {
        self.post("/auth/login/begin", &serde_json::json!({ "email": email }), None).await
    }

    pub async fn complete_login(&self, req: CompleteLoginRequest) -> Result<SessionResponse> {
        self.post("/auth/login/complete", &req, None).await
    }

    // ── Session ─────────────────────────────────────────────────────────────

    pub async fn verify_session(&self, token: &str) -> Result<SessionInfo> {
        self.get("/auth/session", token).await
    }

    pub async fn refresh_session(&self, token: &str) -> Result<SessionResponse> {
        self.post("/auth/session/refresh", &serde_json::json!({}), Some(token)).await
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        let _: serde_json::Value =
            self.post("/auth/session/logout", &serde_json::json!({}), Some(token)).await?;
        Ok(())
    }

    // ── Reset ────────────────────────────────────────────────────────────────

    pub async fn begin_reset(&self, email: &str) -> Result<BeginRegistrationResponse> {
        self.post("/auth/reset/begin", &serde_json::json!({ "email": email }), None).await
    }

    pub async fn complete_reset(&self, req: CompleteResetRequest) -> Result<SessionResponse> {
        self.post("/auth/reset/complete", &req, None).await
    }

    // ── Recovery ────────────────────────────────────────────────────────────

    pub async fn generate_recovery_codes(&self, token: &str) -> Result<RecoveryCodesResponse> {
        self.post("/auth/recovery/generate", &serde_json::json!({}), Some(token)).await
    }

    pub async fn recover_with_code(&self, req: RecoveryRequest) -> Result<SessionResponse> {
        self.post("/auth/recovery/use", &req, None).await
    }

    // ── Devices ──────────────────────────────────────────────────────────────

    pub async fn list_devices(&self, token: &str) -> Result<DevicesResponse> {
        self.get("/auth/devices", token).await
    }

    pub async fn begin_add_device(&self, token: &str) -> Result<BeginRegistrationResponse> {
        self.post("/auth/devices/add/begin", &serde_json::json!({}), Some(token)).await
    }

    pub async fn complete_add_device(&self, req: CompleteAddDeviceRequest) -> Result<Device> {
        self.post("/auth/devices/add/complete", &req, None).await
    }

    pub async fn revoke_device(&self, token: &str, device_id: &str) -> Result<()> {
        self.delete(&format!("/auth/devices/{}", device_id), token).await
    }
}
