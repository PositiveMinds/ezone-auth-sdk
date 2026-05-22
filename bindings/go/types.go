package ezone

import "fmt"

// ─── Response types ───────────────────────────────────────────────────────────

// PendingAuth is returned when a magic-link flow is initiated.
// Embed MagicToken in an email link sent to the user.
type PendingAuth struct {
	MagicToken string `json:"magic_token"`
	ExpiresAt  int64  `json:"expires_at"`
}

// LoginChallenge is returned from BeginLogin.
// The Challenge bytes must be signed by the device's private key.
type LoginChallenge struct {
	Challenge string `json:"challenge"` // base64url
	ExpiresAt int64  `json:"expires_at"`
}

// AuthSession is returned after a successful register / login / reset.
// Use Token in the Authorization header on subsequent requests.
type AuthSession struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	DeviceID  string `json:"device_id"`
	ExpiresAt int64  `json:"expires_at"`
}

// SessionInfo is returned from VerifySession.
type SessionInfo struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	DeviceID  string `json:"device_id"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// RefreshedSession is returned from RefreshSession.
type RefreshedSession struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// RecoveryCodes is returned from GenerateRecoveryCodes.
// Show codes to the user exactly once — only HMAC hashes are stored server-side.
type RecoveryCodes struct {
	Codes []string `json:"codes"`
}

// PendingAddDevice is returned from BeginAddDevice.
type PendingAddDevice struct {
	AddToken  string `json:"add_token"`
	ExpiresAt int64  `json:"expires_at"`
}

// Device represents a registered authentication device.
type Device struct {
	DeviceID  string `json:"device_id"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"created_at"`
	Revoked   bool   `json:"revoked"`
}

// DeviceList wraps the devices list response.
type DeviceList struct {
	Devices []Device `json:"devices"`
}

// ─── Error ────────────────────────────────────────────────────────────────────

// EzoneError is returned when the ezone server responds with a non-2xx status.
type EzoneError struct {
	Message    string
	StatusCode int
}

func (e *EzoneError) Error() string {
	return fmt.Sprintf("ezone: %s (HTTP %d)", e.Message, e.StatusCode)
}
