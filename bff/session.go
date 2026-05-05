package bff

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Stateless session cookies. The cookie carries the ManyRows session
// ID directly (HMAC-signed for tamper-protection); ManyRows is the
// authoritative session store. The BFF backend keeps no server-side
// session state, which means:
//
//  1. Process restarts (deploys, dyno cycling) don't log users out.
//  2. Multi-instance scale-out works without a shared store.
//  3. No DB / Redis dependency for session state.
//
// On revocation: ManyRows owns session lifetime. If a session is
// revoked there (logout, expiry, admin action), the next /bff/proxy/*
// call returns 401 and the proxy clears the cookie.

// cookiePayload is what ends up in the cookie value (base64url-encoded
// JSON, then "." then base64url-encoded HMAC signature). Tiny — only
// what the BFF proxy actually needs to forward to ManyRows.
type cookiePayload struct {
	SessionID string `json:"sid"`
	UserID    string `json:"uid,omitempty"`
	ExpiresAt int64  `json:"exp"` // unix seconds; cookie won't decode after this
}

// SessionManager carries the cookie-config + signing key and exposes
// the LoadAndSave middleware + PutSession / Clear / *FromContext
// helpers. Construct once at app boot and share across handlers
// (immutable after construction).
type SessionManager struct {
	cookieName     string
	cookiePath     string
	cookieDomain   string
	cookieLifetime time.Duration
	cookieSecure   bool
	cookieSameSite http.SameSite
	signingKey     []byte
}

// SessionManagerOpts tunes NewSessionManager. Zero values use
// production-safe defaults documented per-field.
type SessionManagerOpts struct {
	// SigningKey is the HMAC-SHA256 key used to sign session cookies.
	// REQUIRED. Must be at least 32 bytes. Load from a stable source
	// (env var, secret manager) — if the key changes between deploys,
	// every existing cookie becomes invalid and users are logged out.
	//
	// Treat this as a long-lived secret like JWT_SIGNING_KEY: rotate
	// only when compromise is suspected, never on a regular schedule.
	SigningKey []byte

	// CookieName is the cookie name on the user's browser. Defaults
	// to "manyrows_session". Change to coexist with another session
	// cookie at the same path.
	CookieName string

	// CookiePath scopes the cookie. Defaults to "/". Tighten to a
	// subpath only if your app's API routes are also under it
	// (otherwise the proxy won't get the cookie).
	CookiePath string

	// CookieDomain leaves the cookie host-only when empty (the most
	// secure default — only the origin that set it can read it).
	// Set to ".example.com" for cookie sharing across subdomains.
	CookieDomain string

	// Lifetime is the cookie's Max-Age and the embedded payload
	// expiry. Default 30 days. Should match (or be shorter than) the
	// ManyRows app's session TTL — the cookie outliving the ManyRows
	// session just means /bff/proxy/* returns 401 and we clear the
	// cookie on the response.
	Lifetime time.Duration

	// Secure flags the cookie as HTTPS-only. Default true. Override
	// to false ONLY for local dev against a non-HTTPS dev server.
	// Never ship false in production.
	Secure *bool

	// SameSite controls when the cookie is sent on cross-origin
	// requests. Default http.SameSiteLaxMode — works for OAuth
	// redirects (which arrive as top-level GETs) and most app flows.
	// Use SameSiteStrictMode if you don't need the OAuth-redirect
	// case to work.
	SameSite http.SameSite
}

// NewSessionManager builds a SessionManager. Panics if SigningKey is
// missing or shorter than 32 bytes — better to fail at boot than to
// ship with insecure cookies.
func NewSessionManager(opts SessionManagerOpts) *SessionManager {
	if len(opts.SigningKey) < 32 {
		panic("manyrows: bff.SessionManagerOpts.SigningKey must be at least 32 bytes (load from a stable secret like an env var)")
	}
	mgr := &SessionManager{
		signingKey: append([]byte(nil), opts.SigningKey...), // defensive copy
	}
	mgr.cookieLifetime = opts.Lifetime
	if mgr.cookieLifetime == 0 {
		mgr.cookieLifetime = 30 * 24 * time.Hour
	}
	mgr.cookieName = opts.CookieName
	if mgr.cookieName == "" {
		mgr.cookieName = "manyrows_session"
	}
	mgr.cookiePath = opts.CookiePath
	if mgr.cookiePath == "" {
		mgr.cookiePath = "/"
	}
	mgr.cookieDomain = opts.CookieDomain
	if opts.Secure == nil {
		mgr.cookieSecure = true
	} else {
		mgr.cookieSecure = *opts.Secure
	}
	if opts.SameSite != 0 {
		mgr.cookieSameSite = opts.SameSite
	} else {
		mgr.cookieSameSite = http.SameSiteLaxMode
	}
	return mgr
}

// sessionCtxKey is the context key for the per-request session state.
type sessionCtxKey struct{}

// sessionState holds what was loaded from the inbound cookie plus any
// pending mutations the handler made via PutSession / Clear.
type sessionState struct {
	sessionID  string
	userID     string
	pendingSet *cookiePayload
	pendingDel bool
}

func stateFromContext(ctx context.Context) *sessionState {
	v, _ := ctx.Value(sessionCtxKey{}).(*sessionState)
	return v
}

// LoadAndSave is the middleware that reads the inbound cookie into
// request context (so SessionIDFromContext works downstream) and
// writes any cookie mutations queued by PutSession / Clear back on
// the response.
func (m *SessionManager) LoadAndSave(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := &sessionState{}

		if c, err := r.Cookie(m.cookieName); err == nil {
			if p, ok := m.decodeCookie(c.Value); ok {
				state.sessionID = p.SessionID
				state.userID = p.UserID
			}
		}

		ctx := context.WithValue(r.Context(), sessionCtxKey{}, state)

		// Wrap the response writer so we can set the cookie just-in-time
		// before the headers are flushed. Standard http.ResponseWriter
		// pattern: intercept WriteHeader / Write / Flush and run our
		// cookie-applying hook on the first one.
		bw := &cookieResponseWriter{
			ResponseWriter: w,
			mgr:            m,
			state:          state,
		}
		next.ServeHTTP(bw, r.WithContext(ctx))
		bw.applyOnce()
	})
}

// PutSession queues a Set-Cookie for the response carrying the given
// ManyRows session. Idempotent within a request — last call wins.
func (m *SessionManager) PutSession(ctx context.Context, s *Session) error {
	state := stateFromContext(ctx)
	if state == nil {
		return errors.New("manyrows: PutSession called outside LoadAndSave middleware")
	}
	state.pendingSet = &cookiePayload{
		SessionID: s.SessionID,
		UserID:    s.UserID,
		ExpiresAt: time.Now().Add(m.cookieLifetime).Unix(),
	}
	state.pendingDel = false
	state.sessionID = s.SessionID
	state.userID = s.UserID
	return nil
}

// SessionIDFromContext returns the ManyRows session ID loaded from
// the cookie. Empty when the user isn't logged in (no cookie, bad
// signature, or expired payload).
func (m *SessionManager) SessionIDFromContext(ctx context.Context) string {
	state := stateFromContext(ctx)
	if state == nil {
		return ""
	}
	return state.sessionID
}

// UserIDFromContext returns the user ID stored alongside the session
// ID. Convenience for handlers that want the user without making a
// /a/me round trip.
func (m *SessionManager) UserIDFromContext(ctx context.Context) string {
	state := stateFromContext(ctx)
	if state == nil {
		return ""
	}
	return state.userID
}

// Clear queues a cookie deletion on the response. Called from
// Handlers.Logout after Client.Logout has revoked the session in
// ManyRows.
func (m *SessionManager) Clear(ctx context.Context) error {
	state := stateFromContext(ctx)
	if state == nil {
		return errors.New("manyrows: Clear called outside LoadAndSave middleware")
	}
	state.pendingDel = true
	state.pendingSet = nil
	state.sessionID = ""
	state.userID = ""
	return nil
}

// ---------- internals ----------

func (m *SessionManager) encodeCookie(p cookiePayload) (string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	bodyB64 := base64.RawURLEncoding.EncodeToString(body)

	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte(bodyB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return bodyB64 + "." + sig, nil
}

// decodeCookie parses + verifies a cookie value. Returns ok=false on
// any failure (bad encoding, signature mismatch, expired). Callers
// treat ok=false as "no session".
func (m *SessionManager) decodeCookie(s string) (cookiePayload, bool) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return cookiePayload{}, false
	}
	bodyB64, sigB64 := parts[0], parts[1]

	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte(bodyB64))
	expected := mac.Sum(nil)

	provided, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || !hmac.Equal(expected, provided) {
		return cookiePayload{}, false
	}

	body, err := base64.RawURLEncoding.DecodeString(bodyB64)
	if err != nil {
		return cookiePayload{}, false
	}

	var p cookiePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return cookiePayload{}, false
	}
	if time.Now().Unix() > p.ExpiresAt {
		return cookiePayload{}, false
	}
	return p, true
}

func (m *SessionManager) buildSetCookie(p cookiePayload) (*http.Cookie, error) {
	value, err := m.encodeCookie(p)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     m.cookieName,
		Value:    value,
		Path:     m.cookiePath,
		Domain:   m.cookieDomain,
		Expires:  time.Unix(p.ExpiresAt, 0),
		MaxAge:   int(time.Until(time.Unix(p.ExpiresAt, 0)).Seconds()),
		Secure:   m.cookieSecure,
		HttpOnly: true,
		SameSite: m.cookieSameSite,
	}, nil
}

func (m *SessionManager) buildDeleteCookie() *http.Cookie {
	return &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     m.cookiePath,
		Domain:   m.cookieDomain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   m.cookieSecure,
		HttpOnly: true,
		SameSite: m.cookieSameSite,
	}
}

// cookieResponseWriter applies the pending cookie change to the
// response just before headers are written. This is the standard Go
// pattern for "set Set-Cookie headers from middleware that runs after
// the handler" — interceptor on Write / WriteHeader / Flush.
type cookieResponseWriter struct {
	http.ResponseWriter
	mgr     *SessionManager
	state   *sessionState
	applied bool
}

func (b *cookieResponseWriter) applyOnce() {
	if b.applied {
		return
	}
	b.applied = true

	if b.state.pendingSet != nil {
		if c, err := b.mgr.buildSetCookie(*b.state.pendingSet); err == nil {
			http.SetCookie(b.ResponseWriter, c)
		}
		return
	}
	if b.state.pendingDel {
		http.SetCookie(b.ResponseWriter, b.mgr.buildDeleteCookie())
	}
}

func (b *cookieResponseWriter) WriteHeader(status int) {
	b.applyOnce()
	b.ResponseWriter.WriteHeader(status)
}

func (b *cookieResponseWriter) Write(p []byte) (int, error) {
	b.applyOnce()
	return b.ResponseWriter.Write(p)
}

// Flush forwards to the underlying ResponseWriter when it implements
// http.Flusher (chi's router wrapping does). Apply the cookie first
// since Flush will commit headers.
func (b *cookieResponseWriter) Flush() {
	b.applyOnce()
	if f, ok := b.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
