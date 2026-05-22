---
id: go
title: Go
---

# Go SDK

Context-aware, stdlib-only HTTP client with idiomatic Go error handling.

## Installation

```bash
go get github.com/ezone-sdk/ezone-go
```

## Quick start

```go
package main

import (
    "context"
    "fmt"
    ezone "github.com/ezone-sdk/ezone-go"
)

func main() {
    client := ezone.NewClient("https://auth.yourapp.com")

    // Registration
    reg, err := client.BeginRegistration(context.Background(),
        ezone.BeginRegistrationRequest{Email: "alice@example.com"},
    )
    if err != nil { panic(err) }
    fmt.Println("magic token:", reg.MagicToken)

    // Login
    ch, err := client.BeginLogin(context.Background(),
        ezone.BeginLoginRequest{Email: "alice@example.com"},
    )
    if err != nil { panic(err) }

    // sign ch.Challenge with device key...

    session, err := client.CompleteLogin(context.Background(),
        ezone.CompleteLoginRequest{
            Email:           "alice@example.com",
            Challenge:       ch.Challenge,
            Signature:       "<base64url sig>",
            DevicePublicKey: "<base64url SPKI DER>",
        },
    )
    fmt.Println("token:", session.Token)
}
```

## HTTP middleware

```go
import (
    "net/http"
    ezone "github.com/ezone-sdk/ezone-go"
)

func AuthMiddleware(client *ezone.EzoneClient, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        if token == "" {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }

        info, err := client.VerifySession(r.Context(), token)
        if err != nil {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }

        ctx := ezone.WithSession(r.Context(), info)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// In handler:
func handler(w http.ResponseWriter, r *http.Request) {
    session := ezone.SessionFromContext(r.Context())
    fmt.Fprintf(w, "Hello, %s", session.UserID)
}
```

## Full API

```go
type EzoneClient struct { /* ... */ }

func NewClient(baseURL string, opts ...Option) *EzoneClient

func (c *EzoneClient) BeginRegistration(ctx, req) (*BeginRegistrationResponse, error)
func (c *EzoneClient) CompleteRegistration(ctx, req) (*SessionResponse, error)

func (c *EzoneClient) BeginLogin(ctx, req) (*BeginLoginResponse, error)
func (c *EzoneClient) CompleteLogin(ctx, req) (*SessionResponse, error)

func (c *EzoneClient) VerifySession(ctx, token) (*SessionInfo, error)
func (c *EzoneClient) RefreshSession(ctx, token) (*SessionResponse, error)
func (c *EzoneClient) Logout(ctx, token) error

func (c *EzoneClient) BeginReset(ctx, req) (*BeginResetResponse, error)
func (c *EzoneClient) CompleteReset(ctx, req) (*SessionResponse, error)

func (c *EzoneClient) GenerateRecoveryCodes(ctx, token) (*RecoveryCodesResponse, error)
func (c *EzoneClient) RecoverWithCode(ctx, req) (*SessionResponse, error)

func (c *EzoneClient) ListDevices(ctx, token) (*DevicesResponse, error)
func (c *EzoneClient) BeginAddDevice(ctx, token) (*BeginAddDeviceResponse, error)
func (c *EzoneClient) CompleteAddDevice(ctx, req) (*Device, error)
func (c *EzoneClient) RevokeDevice(ctx, token, deviceID string) error
```
