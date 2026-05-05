package bff

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixedKey is a 32-byte test key. Use a different one in tests that
// specifically test signature mismatch.
var fixedKey = bytes.Repeat([]byte{0x42}, 32)

func newMgr(t *testing.T) *SessionManager {
	t.Helper()
	return NewSessionManager(SessionManagerOpts{
		SigningKey: fixedKey,
	})
}

func TestNewSessionManager_PanicsOnShortKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on short signing key")
		}
	}()
	NewSessionManager(SessionManagerOpts{SigningKey: []byte("short")})
}

func TestNewSessionManager_PanicsOnMissingKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on missing signing key")
		}
	}()
	NewSessionManager(SessionManagerOpts{})
}

func TestCookie_RoundTrip(t *testing.T) {
	mgr := newMgr(t)
	p := cookiePayload{
		SessionID: "sess_123",
		UserID:    "u_42",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	encoded, err := mgr.encodeCookie(p)
	if err != nil {
		t.Fatalf("encodeCookie: %v", err)
	}
	got, ok := mgr.decodeCookie(encoded)
	if !ok {
		t.Fatal("decodeCookie returned ok=false on its own output")
	}
	if got.SessionID != p.SessionID || got.UserID != p.UserID {
		t.Errorf("got %+v want %+v", got, p)
	}
}

func TestCookie_RejectsTamperedSignature(t *testing.T) {
	mgr := newMgr(t)
	p := cookiePayload{
		SessionID: "sess_123",
		UserID:    "u_42",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	encoded, _ := mgr.encodeCookie(p)
	// Replace one char in the middle of the signature segment to be
	// sure the decoded bytes change (single-char swaps at the
	// boundary can be base64-equivalent depending on padding).
	parts := strings.Split(encoded, ".")
	sig := parts[1]
	mid := len(sig) / 2
	flip := byte('A')
	if sig[mid] == 'A' {
		flip = 'B'
	}
	parts[1] = sig[:mid] + string(flip) + sig[mid+1:]
	tampered := parts[0] + "." + parts[1]
	if _, ok := mgr.decodeCookie(tampered); ok {
		t.Fatal("decodeCookie accepted tampered signature")
	}
}

func TestCookie_RejectsExpired(t *testing.T) {
	mgr := newMgr(t)
	p := cookiePayload{
		SessionID: "sess_123",
		UserID:    "u_42",
		ExpiresAt: time.Now().Add(-time.Minute).Unix(), // already expired
	}
	encoded, _ := mgr.encodeCookie(p)
	if _, ok := mgr.decodeCookie(encoded); ok {
		t.Fatal("decodeCookie accepted expired payload")
	}
}

func TestCookie_RejectsDifferentKey(t *testing.T) {
	mgr1 := NewSessionManager(SessionManagerOpts{SigningKey: bytes.Repeat([]byte{0x01}, 32)})
	mgr2 := NewSessionManager(SessionManagerOpts{SigningKey: bytes.Repeat([]byte{0x02}, 32)})

	encoded, _ := mgr1.encodeCookie(cookiePayload{
		SessionID: "sess_x",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if _, ok := mgr2.decodeCookie(encoded); ok {
		t.Fatal("mgr2 accepted cookie signed by mgr1's key — signature check is not actually verifying")
	}
}

func TestLoadAndSave_PutAndRead(t *testing.T) {
	mgr := newMgr(t)

	var capturedID string
	handler := mgr.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First request: no cookie yet.
		capturedID = mgr.SessionIDFromContext(r.Context())
		_ = mgr.PutSession(r.Context(), &Session{
			SessionID: "sess_abc",
			UserID:    "u_99",
		})
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if capturedID != "" {
		t.Errorf("expected empty session ID on no-cookie request, got %q", capturedID)
	}

	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "manyrows_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("PutSession did not set a session cookie")
	}
	if !sessionCookie.HttpOnly || !sessionCookie.Secure {
		t.Errorf("cookie should be HttpOnly+Secure by default, got %+v", sessionCookie)
	}

	// Second request: send the cookie back, expect to read the session ID.
	var roundTripID string
	handler2 := mgr.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roundTripID = mgr.SessionIDFromContext(r.Context())
	}))
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	handler2.ServeHTTP(rec2, req2)

	if roundTripID != "sess_abc" {
		t.Errorf("round-trip session ID: got %q want %q", roundTripID, "sess_abc")
	}
}

func TestLoadAndSave_Clear(t *testing.T) {
	mgr := newMgr(t)

	// Set a cookie, then issue a request with Clear.
	encoded, _ := mgr.encodeCookie(cookiePayload{
		SessionID: "sess_to_clear",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	existing := &http.Cookie{Name: "manyrows_session", Value: encoded}

	handler := mgr.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = mgr.Clear(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(existing)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	var deletion *http.Cookie
	for _, c := range cookies {
		if c.Name == "manyrows_session" {
			deletion = c
			break
		}
	}
	if deletion == nil {
		t.Fatal("Clear did not set a deletion cookie")
	}
	if deletion.MaxAge >= 0 {
		t.Errorf("deletion cookie should have MaxAge<0, got %d", deletion.MaxAge)
	}
}

func TestPutSession_OutsideMiddlewareReturnsError(t *testing.T) {
	mgr := newMgr(t)
	if err := mgr.PutSession(t.Context(), &Session{SessionID: "x"}); err == nil {
		t.Fatal("expected error when PutSession called outside LoadAndSave")
	}
}

func TestSecureFalse_OptIn(t *testing.T) {
	insecure := false
	mgr := NewSessionManager(SessionManagerOpts{
		SigningKey: fixedKey,
		Secure:     &insecure,
	})

	handler := mgr.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = mgr.PutSession(r.Context(), &Session{SessionID: "s"})
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == "manyrows_session" {
			if c.Secure {
				t.Error("Secure=false opt-in did not propagate to cookie")
			}
			return
		}
	}
	t.Fatal("session cookie not set")
}
