// Package auth verifies ManyRows-issued bearer JWTs locally using
// the install's JWKS document, then stashes the userID on the
// request context for downstream handlers.
//
// Tokens are signed ES256. The verifier fetches
// `${manyrowsBaseURL}/.well-known/jwks.json` once at first verify,
// caches the parsed keys for `jwksCacheTTL`, and refetches on a kid
// mismatch (so a server-side rotation propagates without a restart).
//
// No round trip per request; no shared secret. The middleware's
// public surface (Middleware, UserIDFromContext, MustUserID) is
// unchanged from the previous /a/me-based implementation —
// customers re-import and rebuild, no code changes on their side.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const userIDKey contextKey = "userID"

// jwksCacheTTL is how long a fetched JWKS is trusted before a
// background-style refetch is triggered. Aligned with the
// other-language SDKs (Node/Python/Java) around 10 minutes — long
// enough to absorb steady-state load, short enough that an
// emergency key rotation on the server reaches all replicas in
// ~10 min without an SDK restart. Previously 1 hour, which left
// Go deployments lagging Node/Python on rotation propagation.
const jwksCacheTTL = 10 * time.Minute

// UserIDFromContext extracts the manyrows user ID from the request context.
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDKey).(string)
	return id, ok && id != ""
}

// MustUserID extracts the user ID from context, panicking if absent.
// Only use in handlers behind auth Middleware, which guarantees the ID is set.
func MustUserID(ctx context.Context) string {
	id, ok := UserIDFromContext(ctx)
	if !ok {
		panic("auth: MustUserID called without authenticated context")
	}
	return id
}

// Middleware verifies Bearer JWTs against the ManyRows install's
// JWKS, checks the aud claim binds to this app, stores the resulting
// user ID in request context, and 401s any request that's missing,
// fails verification, or carries a token minted for a different app.
//
// The aud check matters when two apps share an eTLD: cookies on the
// parent domain ride to every subdomain, so without an explicit
// audience boundary a prod token would be accepted by staging (and
// vice-versa). The check parses the cookie's appID out of `aud` and
// rejects anything that doesn't match the appID this middleware was
// configured for.
func Middleware(manyrowsBaseURL, workspaceSlug, appID string) func(http.Handler) http.Handler {
	// Reject misconfigured baseURL at construction. JWKS fetches over
	// plain HTTP let a network attacker substitute keys and forge any
	// JWT; this is a fatal config error the customer needs to see
	// immediately, not a runtime 5xx after deploy. Localhost stays
	// allowed so dev loops aren't blocked.
	if err := requireSecureBaseURL(manyrowsBaseURL); err != nil {
		panic("manyrows-go auth: " + err.Error())
	}
	v := newVerifier(manyrowsBaseURL, appID)
	_ = workspaceSlug // reserved for future per-workspace checks

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r, appID)
			if token == "" {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			userID, err := v.verify(r.Context(), token)
			if err != nil {
				log.Printf("auth middleware: verify failed: %v", err)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// accessCookiePrefix matches manyrows-core's clientauth.AccessCookieName(appID).
// The SDK can't import that package (cyclic between manyrows-go and
// manyrows-core), so the convention is duplicated here. Keep in sync if
// the server-side name ever changes. Full name is "mr_at_<appID>".
const accessCookiePrefix = "mr_at_"

// bearerToken returns the JWT to verify, picked from (in order):
//  1. Authorization: Bearer <jwt>  — local/Tier-1 mode and any caller
//     that forwards the SDK's Bearer header.
//  2. mr_at_<appID> cookie         — cookie mode: the SDK uses HttpOnly
//     cookies and never attaches a Bearer header. Browsers send the
//     cookie on same-site requests automatically when the customer's
//     auth host and app host share a registrable domain. The cookie
//     name is per-app so two apps on the same eTLD don't overwrite
//     each other.
func bearerToken(r *http.Request, appID string) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(h, "Bearer ") {
		if t := strings.TrimSpace(h[7:]); t != "" {
			return t
		}
	}
	if appID != "" {
		if c, err := r.Cookie(accessCookiePrefix + appID); err == nil && c != nil {
			return strings.TrimSpace(c.Value)
		}
	}
	return ""
}

// verifier owns the JWKS cache and runs the local signature check.
// One per Middleware instance so each (baseURL) keeps its own keys.
// expectedAppID is the app this middleware was configured for; the
// JWT's aud claim must contain it or the token is rejected.
type verifier struct {
	jwksURL       string
	expectedAppID string
	// expectedIss is the install URL the SDK was configured for, used
	// to validate the JWT's iss claim. The server publishes JWTs whose
	// iss == the install base URL (or per-app AuthDomain — customers
	// using AuthDomain must point manyrowsBaseURL at their AuthDomain,
	// not the install URL, so JWKS and iss both line up).
	expectedIss string

	mu        sync.RWMutex
	keysByKID map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

func newVerifier(manyrowsBaseURL, expectedAppID string) *verifier {
	trimmed := strings.TrimRight(manyrowsBaseURL, "/")
	return &verifier{
		jwksURL:       trimmed + "/.well-known/jwks.json",
		expectedAppID: expectedAppID,
		expectedIss:   trimmed,
	}
}

// requireSecureBaseURL rejects baseURL values that would make JWKS
// fetches MITM-able. Only https://… is accepted, with the usual
// localhost / 127.0.0.1 / [::1] dev exceptions so local round-trips
// don't force operators into self-signed cert dances.
func requireSecureBaseURL(raw string) error {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return errors.New("baseURL is empty")
	}
	if strings.HasPrefix(s, "https://") {
		return nil
	}
	for _, prefix := range []string{
		"http://localhost",
		"http://127.0.0.1",
		"http://[::1]",
	} {
		if strings.HasPrefix(s, prefix) {
			return nil
		}
	}
	return fmt.Errorf("baseURL must use https:// (got %q) — refusing to fetch JWKS over plaintext", raw)
}

// verify parses the bearer, looks up the kid in cache (refetching
// on miss or expiry), and validates signature + standard claims.
// Returns the `sub` claim on success.
func (v *verifier) verify(ctx context.Context, token string) (string, error) {
	parsed, err := jwt.Parse(token,
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
			}
			kid, _ := t.Header["kid"].(string)
			return v.keyByKID(ctx, kid)
		},
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithLeeway(60*time.Second), // tolerate ±60s clock skew
	)
	if err != nil {
		return "", err
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("unexpected claims shape")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", errors.New("missing sub claim")
	}
	// iss check: defence-in-depth against cross-install token replay.
	// The server's own signature already binds the token to the install
	// (it's signed with the install's private key), but if a single
	// signing key were ever shared across deployments — operator error,
	// or a future "promoted from staging" migration — this catch
	// surfaces it instead of silently accepting. Skipped when
	// expectedIss is empty (shouldn't happen via Middleware, but
	// keeps the verifier usable in tests that build it directly).
	if v.expectedIss != "" {
		iss, _ := claims["iss"].(string)
		if !issMatches(iss, v.expectedIss) {
			return "", fmt.Errorf("iss claim %q does not match configured baseURL %q", iss, v.expectedIss)
		}
	}
	// aud check: refuse tokens minted for a different app on this
	// install. Catches the cross-app cookie ride-along between sibling
	// subdomains (prod token reaching staging on the same eTLD). Empty
	// expectedAppID is a permissive escape hatch for callers that just
	// want signature-only verification — current Middleware always
	// passes one through.
	if v.expectedAppID != "" {
		if !audMatches(claims["aud"], v.expectedAppID) {
			return "", errors.New("aud claim does not match configured appID")
		}
	}
	return sub, nil
}

// issMatches compares the JWT's iss claim to the configured baseURL,
// tolerating an optional trailing "/" on either side. The server can
// be configured with or without the slash; we don't want the operator
// to have to think about which.
func issMatches(claim, expected string) bool {
	return strings.TrimRight(claim, "/") == strings.TrimRight(expected, "/")
}

// audMatches handles both shapes RFC 7519 allows for `aud`: a single
// string or an array of strings. Matches when the configured appID
// appears anywhere in the claim.
func audMatches(raw interface{}, expected string) bool {
	switch v := raw.(type) {
	case string:
		return v == expected
	case []interface{}:
		for _, x := range v {
			if s, ok := x.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// keyByKID returns the public key for the given kid, fetching JWKS
// from the issuer if the cache is empty / stale or the kid isn't
// known. A refetch on unknown kid is bounded to once per call so a
// stream of bad kids can't pin us against the network.
func (v *verifier) keyByKID(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	v.mu.RLock()
	cached, hit := v.keysByKID[kid]
	stale := time.Since(v.fetchedAt) > jwksCacheTTL
	v.mu.RUnlock()
	if hit && !stale {
		return cached, nil
	}
	if err := v.refresh(ctx); err != nil {
		// Fall back to a stale cached key if we have one — better to
		// keep authenticating users than to hard-fail every request
		// during a transient network blip.
		if hit {
			return cached, nil
		}
		return nil, err
	}
	v.mu.RLock()
	k, ok := v.keysByKID[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown kid: %s", kid)
	}
	return k, nil
}

func (v *verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "manyrows-go-auth/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("jwks read: %w", err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return fmt.Errorf("jwks parse: %w", err)
	}
	v.mu.Lock()
	v.keysByKID = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

// jwksDoc / jwk are the wire shape of /.well-known/jwks.json. We
// only consume the EC P-256 path today; non-EC entries are skipped
// rather than erroring so a future server that publishes mixed key
// types stays compatible.
type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWKS(body []byte) (map[string]*ecdsa.PublicKey, error) {
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" {
			continue
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			continue
		}
		out[k.Kid] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no usable EC P-256 keys in JWKS")
	}
	return out, nil
}
