// Package ezone provides a Go client for the ezone passwordless auth SDK.
//
// Quick start:
//
//	client := ezone.NewClient("https://auth.yourapp.com")
//
//	// Registration
//	pending, _ := client.BeginRegistration(ctx, "alice@example.com")
//	// email pending.MagicToken to alice...
//	session, _ := client.CompleteRegistration(ctx, token, publicKeyB64url, "Laptop")
//
//	// Login
//	challenge, _ := client.BeginLogin(ctx, "alice@example.com")
//	// device signs challenge.Challenge, returns signature...
//	session, _ = client.CompleteLogin(ctx, challenge.Challenge, sig, pubKey)
//
//	// Verify on every protected request
//	info, _ := client.VerifySession(ctx, r.Header.Get("Authorization")[7:])
package ezone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the ezone REST API client.
// It is safe for concurrent use.
type Client struct {
	base   string
	http   *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient replaces the default HTTP client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) { cl.http = c }
}

// WithTimeout sets the per-request timeout (default: 10s).
func WithTimeout(d time.Duration) ClientOption {
	return func(cl *Client) { cl.http.Timeout = d }
}

// NewClient creates a new ezone client targeting baseURL.
// baseURL should not have a trailing slash, e.g. "https://auth.yourapp.com".
func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{
		base: baseURL + "/v1",
		http: &http.Client{Timeout: 10 * time.Second},
	}
	for _, o := range opts { o(c) }
	return c
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

func (c *Client) do(ctx context.Context, method, path string,
	body any, token string, out any) error {

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("ezone: marshal: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bodyReader)
	if err != nil {
		return fmt.Errorf("ezone: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("ezone: request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Error
		if msg == "" {
			msg = resp.Status
		}
		return &EzoneError{Message: msg, StatusCode: resp.StatusCode}
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("ezone: decode response: %w", err)
		}
	}
	return nil
}

func (c *Client) get(ctx context.Context, path, token string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, token, out)
}
func (c *Client) post(ctx context.Context, path string, body any, token string, out any) error {
	return c.do(ctx, http.MethodPost, path, body, token, out)
}
func (c *Client) delete(ctx context.Context, path, token string) error {
	return c.do(ctx, http.MethodDelete, path, nil, token, nil)
}

// ─── Health ───────────────────────────────────────────────────────────────────

// Health checks that the server is reachable and returning OK.
func (c *Client) Health(ctx context.Context) error {
	var r map[string]string
	return c.get(ctx, "/health", "", &r)
}

// ─── Registration ─────────────────────────────────────────────────────────────

// BeginRegistration initiates registration for email.
// Embed result.MagicToken in an email link sent to the user.
func (c *Client) BeginRegistration(ctx context.Context, email string) (*PendingAuth, error) {
	var r PendingAuth
	err := c.post(ctx, "/auth/register/begin",
		map[string]string{"email": email}, "", &r)
	return &r, err
}

// CompleteRegistration completes registration once the user clicks the magic link.
// publicKey is a base64url-encoded SubjectPublicKeyInfo DER of the device's P-384 key.
func (c *Client) CompleteRegistration(ctx context.Context,
	magicToken, publicKey, deviceLabel string) (*AuthSession, error) {

	var r AuthSession
	err := c.post(ctx, "/auth/register/complete", map[string]string{
		"magic_token":  magicToken,
		"public_key":   publicKey,
		"device_label": deviceLabel,
	}, "", &r)
	return &r, err
}

// ─── Login ────────────────────────────────────────────────────────────────────

// BeginLogin requests a challenge for email's device to sign.
func (c *Client) BeginLogin(ctx context.Context, email string) (*LoginChallenge, error) {
	var r LoginChallenge
	err := c.post(ctx, "/auth/login/begin",
		map[string]string{"email": email}, "", &r)
	return &r, err
}

// CompleteLogin submits the signed challenge. All three arguments are base64url strings.
func (c *Client) CompleteLogin(ctx context.Context,
	challenge, signature, publicKey string) (*AuthSession, error) {

	var r AuthSession
	err := c.post(ctx, "/auth/login/complete", map[string]string{
		"challenge":  challenge,
		"signature":  signature,
		"public_key": publicKey,
	}, "", &r)
	return &r, err
}

// ─── Session ──────────────────────────────────────────────────────────────────

// VerifySession verifies token and returns session info.
// Use this in HTTP middleware or request guards.
func (c *Client) VerifySession(ctx context.Context, token string) (*SessionInfo, error) {
	var r SessionInfo
	err := c.get(ctx, "/auth/session", token, &r)
	return &r, err
}

// RefreshSession issues a new token with a fresh expiry.
func (c *Client) RefreshSession(ctx context.Context, token string) (*RefreshedSession, error) {
	var r RefreshedSession
	err := c.post(ctx, "/auth/session/refresh", nil, token, &r)
	return &r, err
}

// Logout logs out. Set revokeDevice to permanently block the device.
func (c *Client) Logout(ctx context.Context, token string, revokeDevice bool) error {
	return c.post(ctx, "/auth/logout",
		map[string]any{"revoke_device": revokeDevice}, token, nil)
}

// ─── Account reset ────────────────────────────────────────────────────────────

// BeginReset initiates account reset. Never errors on unknown email.
func (c *Client) BeginReset(ctx context.Context, email string) (*PendingAuth, error) {
	var r PendingAuth
	err := c.post(ctx, "/auth/reset/begin",
		map[string]string{"email": email}, "", &r)
	return &r, err
}

// CompleteReset registers a new device after a reset.
func (c *Client) CompleteReset(ctx context.Context,
	magicToken, publicKey, deviceLabel string) (*AuthSession, error) {

	var r AuthSession
	err := c.post(ctx, "/auth/reset/complete", map[string]string{
		"magic_token":  magicToken,
		"public_key":   publicKey,
		"device_label": deviceLabel,
	}, "", &r)
	return &r, err
}

// ─── Recovery codes ───────────────────────────────────────────────────────────

// GenerateRecoveryCodes generates backup codes for the authenticated user.
// Show codes to the user exactly once.
func (c *Client) GenerateRecoveryCodes(ctx context.Context, token string) (*RecoveryCodes, error) {
	var r RecoveryCodes
	err := c.post(ctx, "/auth/recovery/generate", nil, token, &r)
	return &r, err
}

// RecoverWithCode uses a recovery code to obtain a reset magic token.
// The code is permanently consumed.
func (c *Client) RecoverWithCode(ctx context.Context, email, code string) (*PendingAuth, error) {
	var r PendingAuth
	err := c.post(ctx, "/auth/recovery/use",
		map[string]string{"email": email, "code": code}, "", &r)
	return &r, err
}

// ─── Multi-device ─────────────────────────────────────────────────────────────

// BeginAddDevice starts adding a new device to an authenticated account.
func (c *Client) BeginAddDevice(ctx context.Context, token string) (*PendingAddDevice, error) {
	var r PendingAddDevice
	err := c.post(ctx, "/auth/devices/add/begin", nil, token, &r)
	return &r, err
}

// CompleteAddDevice enrolls a new device.
func (c *Client) CompleteAddDevice(ctx context.Context,
	addToken, publicKey, deviceLabel string) (*AuthSession, error) {

	var r AuthSession
	err := c.post(ctx, "/auth/devices/add/complete", map[string]string{
		"add_token":    addToken,
		"public_key":   publicKey,
		"device_label": deviceLabel,
	}, "", &r)
	return &r, err
}

// ListDevices returns all devices for the authenticated user.
func (c *Client) ListDevices(ctx context.Context, token string) ([]Device, error) {
	var r DeviceList
	err := c.get(ctx, "/auth/devices", token, &r)
	return r.Devices, err
}

// RevokeDevice revokes a device. Requires a session from a different device.
func (c *Client) RevokeDevice(ctx context.Context, token, deviceID string) error {
	return c.delete(ctx, "/auth/devices/"+deviceID, token)
}

// ─── Middleware helper ────────────────────────────────────────────────────────

// BearerMiddleware returns an http.Handler that verifies the Authorization
// header and injects session info into the request context.
//
//	mux.Handle("/api/", ezone.BearerMiddleware(client, mux))
func BearerMiddleware(c *Client, next http.Handler) http.Handler {
	type ctxKey struct{}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		token := auth[7:]

		info, err := c.VerifySession(r.Context(), token)
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKey{}, info)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SessionFromContext retrieves the SessionInfo injected by BearerMiddleware.
func SessionFromContext(ctx context.Context) (*SessionInfo, bool) {
	type ctxKey struct{}
	v, ok := ctx.Value(ctxKey{}).(*SessionInfo)
	return v, ok
}
