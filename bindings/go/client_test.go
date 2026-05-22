package ezone_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ezone "github.com/ezone-sdk/ezone-go"
)

// mockServer stubs the ezone REST API for unit testing without a live server.
func mockServer(t *testing.T) (*httptest.Server, *ezone.Client) {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/v1/auth/register/begin", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"magic_token": "tok.abc123",
			"expires_at":  9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/register/complete", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "session.xyz",
			"user_id":    "user-1",
			"device_id":  "dev-1",
			"expires_at": 9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/login/begin", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"challenge":  "Y2hhbGxlbmdl",
			"expires_at": 9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/login/complete", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "session.abc",
			"user_id":    "user-1",
			"device_id":  "dev-1",
			"expires_at": 9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/session", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"user_id":    "user-1",
			"email":      "alice@example.com",
			"device_id":  "dev-1",
			"issued_at":  1000000000,
			"expires_at": 9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/session/refresh", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "session.new",
			"expires_at": 9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/logout", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/v1/auth/reset/begin", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"magic_token": "reset.tok",
			"expires_at":  9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/reset/complete", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "session.reset",
			"user_id":    "user-1",
			"device_id":  "dev-2",
			"expires_at": 9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/recovery/generate", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"codes": []string{
				"EZONE-ABCD-EFGH-IJKL",
				"EZONE-MNOP-QRST-UVWX",
			},
		})
	})

	mux.HandleFunc("/v1/auth/recovery/use", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"magic_token": "recovery.tok",
			"expires_at":  9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/devices/add/begin", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"add_token":  "add.tok",
			"expires_at": 9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/devices/add/complete", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "session.new-device",
			"user_id":    "user-1",
			"device_id":  "dev-3",
			"expires_at": 9999999999,
		})
	})

	mux.HandleFunc("/v1/auth/devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"devices": []map[string]any{
				{"device_id": "dev-1", "label": "Laptop", "created_at": 1000, "revoked": false},
				{"device_id": "dev-2", "label": "Phone",  "created_at": 2000, "revoked": false},
			},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := ezone.NewClient(srv.URL)
	return srv, client
}

func TestHealth(t *testing.T) {
	_, c := mockServer(t)
	if err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationFlow(t *testing.T) {
	_, c := mockServer(t)
	ctx := context.Background()

	pending, err := c.BeginRegistration(ctx, "alice@example.com")
	if err != nil { t.Fatal(err) }
	if pending.MagicToken == "" { t.Fatal("expected magic_token") }

	session, err := c.CompleteRegistration(ctx, pending.MagicToken, "pubkeyB64", "Laptop")
	if err != nil { t.Fatal(err) }
	if session.Token == "" { t.Fatal("expected token") }
	if session.UserID == "" { t.Fatal("expected user_id") }
}

func TestLoginFlow(t *testing.T) {
	_, c := mockServer(t)
	ctx := context.Background()

	challenge, err := c.BeginLogin(ctx, "alice@example.com")
	if err != nil { t.Fatal(err) }
	if challenge.Challenge == "" { t.Fatal("expected challenge") }

	session, err := c.CompleteLogin(ctx, challenge.Challenge, "sigB64", "pubkeyB64")
	if err != nil { t.Fatal(err) }
	if session.Token == "" { t.Fatal("expected session token") }
}

func TestVerifySession(t *testing.T) {
	_, c := mockServer(t)
	info, err := c.VerifySession(context.Background(), "some.token")
	if err != nil { t.Fatal(err) }
	if info.UserID == "" { t.Fatal("expected user_id") }
	if info.Email == "" { t.Fatal("expected email") }
}

func TestRefreshSession(t *testing.T) {
	_, c := mockServer(t)
	r, err := c.RefreshSession(context.Background(), "old.token")
	if err != nil { t.Fatal(err) }
	if r.Token == "" { t.Fatal("expected new token") }
}

func TestLogout(t *testing.T) {
	_, c := mockServer(t)
	if err := c.Logout(context.Background(), "token", false); err != nil {
		t.Fatal(err)
	}
}

func TestAccountReset(t *testing.T) {
	_, c := mockServer(t)
	ctx := context.Background()

	pending, err := c.BeginReset(ctx, "alice@example.com")
	if err != nil { t.Fatal(err) }

	session, err := c.CompleteReset(ctx, pending.MagicToken, "newPubKey", "New Device")
	if err != nil { t.Fatal(err) }
	if session.Token == "" { t.Fatal("expected token") }
}

func TestRecoveryCodes(t *testing.T) {
	_, c := mockServer(t)
	ctx := context.Background()

	codes, err := c.GenerateRecoveryCodes(ctx, "token")
	if err != nil { t.Fatal(err) }
	if len(codes.Codes) == 0 { t.Fatal("expected recovery codes") }

	pending, err := c.RecoverWithCode(ctx, "alice@example.com", codes.Codes[0])
	if err != nil { t.Fatal(err) }
	if pending.MagicToken == "" { t.Fatal("expected magic_token") }
}

func TestMultiDevice(t *testing.T) {
	_, c := mockServer(t)
	ctx := context.Background()

	pending, err := c.BeginAddDevice(ctx, "token")
	if err != nil { t.Fatal(err) }

	session, err := c.CompleteAddDevice(ctx, pending.AddToken, "newPubKey", "Phone")
	if err != nil { t.Fatal(err) }
	if session.DeviceID == "" { t.Fatal("expected device_id") }

	devices, err := c.ListDevices(ctx, "token")
	if err != nil { t.Fatal(err) }
	if len(devices) == 0 { t.Fatal("expected devices") }

	if err := c.RevokeDevice(ctx, "token", devices[0].DeviceID); err != nil {
		t.Fatal(err)
	}
}

func TestBearerMiddleware(t *testing.T) {
	_, c := mockServer(t)

	protected := ezone.BearerMiddleware(c, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			info, ok := ezone.SessionFromContext(r.Context())
			if !ok || info == nil {
				t.Error("expected session in context")
			}
			w.WriteHeader(http.StatusOK)
		},
	))

	// Valid token
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid.token")
	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// No token
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rr2 := httptest.NewRecorder()
	protected.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr2.Code)
	}
}
