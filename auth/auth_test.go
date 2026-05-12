package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKey is a single ES256 keypair plus a deterministic kid (the
// RFC 7638 thumbprint, mirroring the issuer side). One per test —
// holds everything needed to mint signed tokens AND serve the
// matching JWKS.
type testKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newTestKey(t *testing.T) *testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(leftPad32(priv.PublicKey.X.Bytes()))
	y := base64.RawURLEncoding.EncodeToString(leftPad32(priv.PublicKey.Y.Bytes()))
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)
	sum := sha256.Sum256([]byte(canonical))
	kid := base64.RawURLEncoding.EncodeToString(sum[:])
	return &testKey{priv: priv, kid: kid}
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// signToken mints an ES256 JWT with the test key + given subject. The
// aud claim defaults to "app1" so it matches the Middleware setups in
// every existing test; pass an opts func that sets MapClaims["aud"] to
// something else when a test needs to exercise the aud-mismatch path.
//
// iss defaults to a sentinel that won't match any real server URL —
// every test that runs against a httptest.NewServer threads its own
// srv.URL through withIss so the SDK's iss validation has something
// real to compare against.
func (k *testKey) signToken(t *testing.T, sub string, opts ...func(*jwt.Token)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": sub,
		"aud": "app1",
		"iss": "https://test.invalid",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = k.kid
	for _, opt := range opts {
		opt(tok)
	}
	signed, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// withIss sets the JWT's iss claim. Tests pass their httptest server's
// URL so it matches the Middleware's expectedIss (derived from the
// baseURL the test passes to Middleware).
func withIss(url string) func(*jwt.Token) {
	return func(tok *jwt.Token) {
		tok.Claims.(jwt.MapClaims)["iss"] = url
	}
}

// jwksHandler serves a JWKS doc containing the given keys. callCount
// (if non-nil) is incremented per request — tests assert on it to
// verify caching / refetch behaviour.
func jwksHandler(callCount *int32, keys ...*testKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if callCount != nil {
			atomic.AddInt32(callCount, 1)
		}
		out := map[string]any{"keys": []any{}}
		for _, k := range keys {
			out["keys"] = append(out["keys"].([]any), map[string]string{
				"kty": "EC",
				"crv": "P-256",
				"kid": k.kid,
				"use": "sig",
				"alg": "ES256",
				"x":   base64.RawURLEncoding.EncodeToString(leftPad32(k.priv.PublicKey.X.Bytes())),
				"y":   base64.RawURLEncoding.EncodeToString(leftPad32(k.priv.PublicKey.Y.Bytes())),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

// jwksServer wraps jwksHandler in an httptest.Server registered at
// /.well-known/jwks.json — the path the verifier hard-codes.
func jwksServer(t *testing.T, callCount *int32, keys ...*testKey) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/.well-known/jwks.json", jwksHandler(callCount, keys...))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestUserIDFromContext_Missing(t *testing.T) {
	id, ok := UserIDFromContext(context.Background())
	if ok {
		t.Errorf("expected ok=false, got true with id=%q", id)
	}
}

func TestUserIDFromContext_Empty(t *testing.T) {
	ctx := context.WithValue(context.Background(), userIDKey, "")
	id, ok := UserIDFromContext(ctx)
	if ok {
		t.Errorf("expected ok=false for empty string, got true with id=%q", id)
	}
}

func TestUserIDFromContext_Present(t *testing.T) {
	ctx := context.WithValue(context.Background(), userIDKey, "user-42")
	id, ok := UserIDFromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if id != "user-42" {
		t.Errorf("id = %q, want %q", id, "user-42")
	}
}

func TestMustUserID_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	MustUserID(context.Background())
}

func TestMustUserID_Returns(t *testing.T) {
	ctx := context.WithValue(context.Background(), userIDKey, "user-7")
	id := MustUserID(ctx)
	if id != "user-7" {
		t.Errorf("id = %q, want %q", id, "user-7")
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"Basic abc", ""},
		{"Bearer abc123", "abc123"},
		{"Bearer  spaced ", "spaced"},
		{" Bearer tok ", "tok"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		if tt.header != "" {
			r.Header.Set("Authorization", tt.header)
		}
		got := bearerToken(r, "app1")
		if got != tt.want {
			t.Errorf("bearerToken(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestMiddleware_NoToken(t *testing.T) {
	k := newTestKey(t)
	srv := jwksServer(t, nil, k)
	mw := Middleware(srv.URL, "ws", "app1")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called without token")
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_ValidToken(t *testing.T) {
	k := newTestKey(t)
	srv := jwksServer(t, nil, k)
	mw := Middleware(srv.URL, "ws", "app1")

	var gotID string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := UserIDFromContext(r.Context())
		if !ok {
			t.Fatal("expected user ID in context")
		}
		gotID = id
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+k.signToken(t, "user-55", withIss(srv.URL)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if gotID != "user-55" {
		t.Errorf("user ID = %q, want %q", gotID, "user-55")
	}
}

func TestMiddleware_WrongAudienceRejected(t *testing.T) {
	// Token minted for app2 (e.g. the staging app on the same eTLD)
	// must be rejected by the middleware configured for app1. This is
	// the load-bearing check that keeps prod cookies from riding into
	// staging when both apps share auth.<root>.com / Cookie domain
	// <root>.com.
	k := newTestKey(t)
	srv := jwksServer(t, nil, k)
	mw := Middleware(srv.URL, "ws", "app1")

	tok := k.signToken(t, "u1", withIss(srv.URL), func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["aud"] = "app2"
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run when aud points at a different app")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (cross-app token must be rejected)", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_AudArrayMatches(t *testing.T) {
	// aud claim is allowed to be an array of strings per RFC 7519.
	// Match if the configured appID appears anywhere in the array.
	k := newTestKey(t)
	srv := jwksServer(t, nil, k)
	mw := Middleware(srv.URL, "ws", "app1")

	tok := k.signToken(t, "u1", withIss(srv.URL), func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["aud"] = []interface{}{"other-app", "app1", "third"}
	})

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !called {
		t.Errorf("array aud containing app1 should be accepted; got status=%d called=%v", rr.Code, called)
	}
}

func TestMiddleware_TamperedToken(t *testing.T) {
	k := newTestKey(t)
	srv := jwksServer(t, nil, k)
	mw := Middleware(srv.URL, "ws", "app1")

	tok := k.signToken(t, "u1", withIss(srv.URL))
	// Flip a char in the MIDDLE of the signature segment. Tweaking
	// the trailing char is unsafe — base64's bit-packing means the
	// last alphabet char often has unused trailing bits, so a swap
	// can decode back to identical bytes.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	sig := parts[2]
	mid := len(sig) / 2
	flip := byte('A')
	if sig[mid] == 'A' {
		flip = 'B'
	}
	tampered := parts[0] + "." + parts[1] + "." + sig[:mid] + string(flip) + sig[mid+1:]

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called with tampered token")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_ExpiredToken(t *testing.T) {
	k := newTestKey(t)
	srv := jwksServer(t, nil, k)
	mw := Middleware(srv.URL, "ws", "app1")

	// Build a token with exp in the past, well beyond the 60s leeway.
	claims := jwt.MapClaims{
		"sub": "u1",
		"aud": "app1",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = k.kid
	signed, _ := tok.SignedString(k.priv)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called with expired token")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_WrongKey(t *testing.T) {
	// JWKS server publishes k1, but the bearer is signed by k2 and
	// announces k1's kid. Verification must fail (signature mismatch).
	k1 := newTestKey(t)
	k2 := newTestKey(t)
	srv := jwksServer(t, nil, k1)
	mw := Middleware(srv.URL, "ws", "app1")

	claims := jwt.MapClaims{
		"sub": "u1",
		"aud": "app1",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = k1.kid
	signed, _ := tok.SignedString(k2.priv)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called when sig mismatch")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_JWKSCachedAcrossRequests(t *testing.T) {
	// Three sequential requests with the same kid should produce
	// exactly one JWKS fetch — anything else means the cache isn't
	// holding.
	k := newTestKey(t)
	var calls int32
	srv := jwksServer(t, &calls, k)
	mw := Middleware(srv.URL, "ws", "app1")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tok := k.signToken(t, "u1", withIss(srv.URL))
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, rr.Code)
		}
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("JWKS fetch count = %d, want 1", got)
	}
}

func TestMiddleware_RefetchOnUnknownKid(t *testing.T) {
	// First request uses k1, succeeds, JWKS cached.
	// Second request announces a kid the cache doesn't have — the
	// verifier must refetch JWKS to pick up any new key. Here the
	// server still only knows k1, so the unknown-kid request fails
	// with 401, but the refetch attempt still happens.
	k1 := newTestKey(t)
	k2 := newTestKey(t)
	var calls int32
	srv := jwksServer(t, &calls, k1)
	mw := Middleware(srv.URL, "ws", "app1")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Warm the cache with a valid k1 token.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+k1.signToken(t, "u1", withIss(srv.URL)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("warm-up: status = %d", rr.Code)
	}
	first := atomic.LoadInt32(&calls)
	if first != 1 {
		t.Fatalf("warm-up JWKS fetches = %d, want 1", first)
	}

	// Now hit it with a token using k2's kid. Cache-miss path should
	// trigger a refetch.
	tok2 := k2.signToken(t, "u2", withIss(srv.URL))
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+tok2)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("unknown-kid: status = %d, want 401", rr2.Code)
	}
	if got := atomic.LoadInt32(&calls); got <= first {
		t.Errorf("expected JWKS refetch on unknown kid; calls before=%d after=%d", first, got)
	}
}

func TestMiddleware_BackendDownAfterCacheWarmed(t *testing.T) {
	// Once the JWKS is in cache, subsequent requests with the same
	// kid must NOT depend on the issuer being reachable — that's the
	// whole point of the cache. (The unknown-kid → stale-fallback
	// branch is exercised in production but inconvenient to test
	// without poking verifier internals; covered indirectly by the
	// refresh-failure code path in keyByKID.)
	k := newTestKey(t)
	var fail atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		jwksHandler(nil, k).ServeHTTP(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mw := Middleware(srv.URL, "ws", "app1")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tok := k.signToken(t, "u1", withIss(srv.URL))

	// Warm the cache.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("warm: status %d", rr.Code)
	}

	// Backend goes away; cached request still authenticates.
	fail.Store(true)
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("cached path with backend down: status = %d, want 200", rr2.Code)
	}
}

// Middleware must refuse plain-http baseURLs (except localhost) so a
// customer typo can't silently turn JWKS-over-MITM into a successful
// verify. Panics at config time so the deploy fails fast.
func TestMiddleware_PanicsOnHTTPBaseURL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for plain-http baseURL")
		}
	}()
	_ = Middleware("http://app.example.com", "ws", "app1")
}

// Localhost http is still allowed so dev loops work without
// self-signed certs.
func TestMiddleware_AcceptsLocalhostHTTP(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic for localhost baseURL: %v", r)
		}
	}()
	_ = Middleware("http://localhost:8080", "ws", "app1")
	_ = Middleware("http://127.0.0.1:8080", "ws", "app1")
	_ = Middleware("https://app.example.com", "ws", "app1")
}

// Token signed by this install but missing iss (or with iss pointing
// at a different deployment) is rejected as a defence-in-depth measure
// against shared-signing-key replay.
func TestMiddleware_RejectsIssMismatch(t *testing.T) {
	k := newTestKey(t)
	srv := jwksServer(t, nil, k)
	mw := Middleware(srv.URL, "ws", "app1")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Wrong iss — server URL but different host:
	tok := k.signToken(t, "u1", withIss("https://other-install.example.com"))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (iss mismatch must reject)", rr.Code)
	}

	// Trailing slash on one side is fine — server may or may not
	// emit it; the operator shouldn't have to think about it.
	tok2 := k.signToken(t, "u1", withIss(srv.URL+"/"))
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+tok2)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("trailing-slash iss: status = %d, want 200", rr2.Code)
	}
}
