package bff

import (
	"context"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
)

// sessionKey is the scs key under which we stash the ManyRows session
// ID. Unexported intentionally — callers don't need to read it
// directly; they use Handlers / Proxy / RequireSession.
const sessionKey = "manyrows.session_id"

// userKey holds the user_id alongside the session id. Convenience for
// customer code that wants the logged-in user without making a
// /api/me round trip.
const userKey = "manyrows.user_id"

// SessionManager wraps scs.SessionManager with sensible defaults for
// the ManyRows BFF use case: HttpOnly, SameSite=Lax, 30-day cookie,
// in-memory store. Customers can swap the store (.Store = scs.NewXxxStore())
// after construction without rebuilding the manager.
//
// scs handles cookie encryption/signing (with a random per-process
// key by default — set Manager.Codec or use a server-side store if
// you need sessions to survive process restarts).
type SessionManager struct {
	*scs.SessionManager
}

// SessionManagerOpts tunes NewSessionManager. Zero values use
// production-safe defaults documented per-field.
type SessionManagerOpts struct {
	// CookieName is the cookie name on the user's browser. Defaults
	// to "manyrows_session". Change if you need to coexist with
	// another session cookie at the same path.
	CookieName string

	// CookiePath scopes the cookie. Defaults to "/". Tighten to
	// "/auth/" only if your app's API routes are also under /auth/
	// (otherwise the proxy won't get the cookie).
	CookiePath string

	// CookieDomain leaves the cookie host-only when empty (the most
	// secure default — only the origin that set it can read it).
	// Set to ".example.com" for cookie sharing across subdomains.
	CookieDomain string

	// Lifetime is how long the cookie+server session stays valid
	// after issuance. Default 30 days. Should match (or be shorter
	// than) the ManyRows app's session TTL — the cookie outliving
	// the ManyRows session just means the proxy gets 401 and clears
	// the cookie on the way out.
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

// NewSessionManager wires scs with the BFF defaults. The returned
// manager has an in-memory store — fine for single-instance Go
// processes (Heroku dyno, single VPS). For multi-instance deployments,
// swap mgr.Store to a Postgres/Redis-backed scs store.
func NewSessionManager(opts SessionManagerOpts) *SessionManager {
	mgr := scs.New()
	if opts.Lifetime == 0 {
		opts.Lifetime = 30 * 24 * time.Hour
	}
	mgr.Lifetime = opts.Lifetime
	if opts.CookieName != "" {
		mgr.Cookie.Name = opts.CookieName
	} else {
		mgr.Cookie.Name = "manyrows_session"
	}
	if opts.CookiePath != "" {
		mgr.Cookie.Path = opts.CookiePath
	} else {
		mgr.Cookie.Path = "/"
	}
	if opts.CookieDomain != "" {
		mgr.Cookie.Domain = opts.CookieDomain
	}
	mgr.Cookie.HttpOnly = true
	if opts.Secure == nil {
		mgr.Cookie.Secure = true
	} else {
		mgr.Cookie.Secure = *opts.Secure
	}
	if opts.SameSite != 0 {
		mgr.Cookie.SameSite = opts.SameSite
	} else {
		mgr.Cookie.SameSite = http.SameSiteLaxMode
	}
	return &SessionManager{mgr}
}

// PutSession records a fresh ManyRows Session in scs's session store
// and arranges for the response cookie to carry the session token on
// the way out. Called from Handlers.Login etc on successful auth.
//
// Replaces any previous session value silently — re-logging in
// invalidates the prior cookie's session ID via scs's RenewToken.
func (m *SessionManager) PutSession(ctx context.Context, s *Session) error {
	if err := m.RenewToken(ctx); err != nil {
		return err
	}
	m.Put(ctx, sessionKey, s.SessionID)
	m.Put(ctx, userKey, s.UserID)
	return nil
}

// SessionIDFromContext reads the ManyRows session ID stored by
// PutSession. Empty when the user isn't logged in. Safe to call from
// any handler downstream of the scs LoadAndSave middleware (which
// Handlers.Mount installs automatically).
func (m *SessionManager) SessionIDFromContext(ctx context.Context) string {
	return m.GetString(ctx, sessionKey)
}

// UserIDFromContext is the convenience equivalent of SessionIDFromContext
// for the user_id stashed alongside.
func (m *SessionManager) UserIDFromContext(ctx context.Context) string {
	return m.GetString(ctx, userKey)
}

// Clear wipes the session from scs's store and the cookie from the
// response. Called from Handlers.Logout after Client.Logout has
// revoked the session in ManyRows.
func (m *SessionManager) Clear(ctx context.Context) error {
	return m.Destroy(ctx)
}
