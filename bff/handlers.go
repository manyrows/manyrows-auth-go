package bff

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// HandlersConfig tunes the auth-route handlers. Zero-valued struct
// uses sensible defaults documented per-field.
type HandlersConfig struct {
	// OAuthRedirectURI is the URL ManyRows redirects the browser to
	// after a successful OAuth callback. MUST match what was passed
	// as `bff_redirect_uri` on /authorize AND what's on the app's
	// allowlist in the ManyRows admin UI. Required for OAuthCallback.
	OAuthRedirectURI string

	// OAuthSuccessRedirect is where OAuthCallback sends the browser
	// after a successful login. Required.
	OAuthSuccessRedirect string

	// OAuthTOTPRedirect is where OAuthCallback sends the user when
	// the OAuth callback returns a TOTP challenge. The challenge token
	// is appended as ?challengeToken=...
	OAuthTOTPRedirect string

	// OAuthErrorRedirect is where OAuthCallback sends the browser on
	// error. Receives ?error=<code>. Required.
	OAuthErrorRedirect string

	// ClientIPExtractor returns the end-user's IP from an incoming
	// browser request. Defaults to ClientIPFromRequest. Override for
	// non-standard proxy setups (e.g. Cloudflare's CF-Connecting-IP).
	ClientIPExtractor func(*http.Request) string
}

// Handlers groups the http.HandlerFuncs the customer mounts on their
// backend. Construct once via NewHandlers and call Mount, or wire each
// HandlerFunc into your router individually.
type Handlers struct {
	Client   *Client
	Sessions *SessionManager
	Cfg      HandlersConfig
}

// NewHandlers binds the SDK pieces. Callers usually do this once at
// app boot and pass it to Mount.
func NewHandlers(client *Client, sessions *SessionManager, cfg HandlersConfig) *Handlers {
	if cfg.ClientIPExtractor == nil {
		cfg.ClientIPExtractor = ClientIPFromRequest
	}
	return &Handlers{Client: client, Sessions: sessions, Cfg: cfg}
}

// Mount wires the standard auth routes onto the given router. Equivalent
// to wiring each HandlerFunc by hand:
//
//	r.HandleFunc("/auth/login",            h.Login)
//	r.HandleFunc("/auth/google",           h.LoginGoogle)
//	r.HandleFunc("/auth/totp/verify",      h.VerifyTOTP)
//	r.HandleFunc("/auth/oauth/callback",   h.OAuthCallback)
//	r.HandleFunc("/auth/logout",           h.Logout)
//
// Customers wanting more control (different paths, extra middleware
// per route) should skip Mount and wire the methods directly.
func (h *Handlers) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/auth/login", h.Login)
	mux.HandleFunc("/auth/google", h.LoginGoogle)
	mux.HandleFunc("/auth/totp/verify", h.VerifyTOTP)
	mux.HandleFunc("/auth/oauth/callback", h.OAuthCallback)
	mux.HandleFunc("/auth/logout", h.Logout)
}

// LoadAndSave wraps the customer's router with the scs session
// middleware AND extracts the browser's IP/User-Agent into context for
// downstream Client / Proxy calls. Use this instead of calling
// Sessions.LoadAndSave directly so the IP/UA forwarding works.
//
//	mux := http.NewServeMux()
//	... mount handlers + Proxy on mux ...
//	http.ListenAndServe(":8080", h.LoadAndSave(mux))
func (h *Handlers) LoadAndSave(next http.Handler) http.Handler {
	withCtx := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if ip := h.Cfg.ClientIPExtractor(r); ip != "" {
			ctx = WithClientIP(ctx, ip)
		}
		if ua := strings.TrimSpace(r.UserAgent()); ua != "" {
			ctx = WithClientUserAgent(ctx, ua)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
	return h.Sessions.LoadAndSave(withCtx)
}

// Login handles POST /auth/login with JSON body {email, password, rememberMe}.
// On success: writes session cookie, returns 200 + {ok:true} (or
// {ok:true, totpRequired:true, challengeToken:"..."} for TOTP step-up).
// On failure: relays ManyRows' error.* code with the same HTTP status.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		RememberMe bool   `json:"rememberMe"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "error.badRequest")
		return
	}
	ses, err := h.Client.LoginPassword(r.Context(), body.Email, body.Password, body.RememberMe)
	if err != nil {
		relayErr(w, err)
		return
	}
	h.completeAuth(w, r, ses)
}

// LoginGoogle handles POST /auth/google with JSON body {credential, rememberMe}.
// `credential` is the Google ID token from the browser-side Google
// Sign-In flow. Same response shape as Login.
func (h *Handlers) LoginGoogle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Credential string `json:"credential"`
		RememberMe bool   `json:"rememberMe"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "error.badRequest")
		return
	}
	ses, err := h.Client.LoginGoogle(r.Context(), body.Credential, body.RememberMe)
	if err != nil {
		relayErr(w, err)
		return
	}
	h.completeAuth(w, r, ses)
}

// VerifyTOTP handles POST /auth/totp/verify with body {challengeToken, code}.
// Used after Login / LoginGoogle returned totpRequired:true. Same
// response shape on success.
func (h *Handlers) VerifyTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ChallengeToken string `json:"challengeToken"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "error.badRequest")
		return
	}
	ses, err := h.Client.VerifyTOTP(r.Context(), body.ChallengeToken, body.Code)
	if err != nil {
		relayErr(w, err)
		return
	}
	h.completeAuth(w, r, ses)
}

// OAuthCallback handles GET /auth/oauth/callback?code=...&state=...
// after ManyRows redirects the user from a provider (Apple / Microsoft /
// GitHub) login. Browser-driven 302 redirects on every branch:
//
//	success            → cfg.OAuthSuccessRedirect
//	totp challenge     → cfg.OAuthTOTPRedirect?challengeToken=...
//	error              → cfg.OAuthErrorRedirect?error=<code>
func (h *Handlers) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errCode := strings.TrimSpace(q.Get("error")); errCode != "" {
		redirectErr(w, r, h.Cfg.OAuthErrorRedirect, errCode)
		return
	}
	code := strings.TrimSpace(q.Get("code"))
	if code == "" {
		redirectErr(w, r, h.Cfg.OAuthErrorRedirect, "missing_code")
		return
	}

	ses, err := h.Client.ExchangeAuthCode(r.Context(), code, h.Cfg.OAuthRedirectURI)
	if err != nil {
		var apiErr *APIError
		errCode := "exchange_failed"
		if asAPIErr(err, &apiErr) && apiErr.Code != "" {
			errCode = apiErr.Code
		}
		redirectErr(w, r, h.Cfg.OAuthErrorRedirect, errCode)
		return
	}

	if ses.TOTPRequired {
		dest := h.Cfg.OAuthTOTPRedirect
		if dest == "" {
			redirectErr(w, r, h.Cfg.OAuthErrorRedirect, "totp_redirect_not_configured")
			return
		}
		dest = appendQuery(dest, "challengeToken", ses.ChallengeToken)
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}

	if err := h.Sessions.PutSession(r.Context(), ses); err != nil {
		redirectErr(w, r, h.Cfg.OAuthErrorRedirect, "session_store_failed")
		return
	}
	http.Redirect(w, r, h.Cfg.OAuthSuccessRedirect, http.StatusFound)
}

// Logout handles POST /auth/logout. Revokes the ManyRows session and
// clears the local cookie. Idempotent — no-op if no session is set.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	sessionID := h.Sessions.SessionIDFromContext(r.Context())
	if sessionID != "" {
		// Best-effort: a network failure to ManyRows shouldn't block
		// the user from logging out locally. The next /api/* call from
		// the browser would 401 anyway, since the cookie is gone.
		_ = h.Client.Logout(r.Context(), sessionID)
	}
	if err := h.Sessions.Clear(r.Context()); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// completeAuth is the shared "session response → cookie + JSON" path
// for Login / LoginGoogle / VerifyTOTP. Branches on TOTPRequired so the
// caller's UI can prompt for the code.
func (h *Handlers) completeAuth(w http.ResponseWriter, r *http.Request, ses *Session) {
	if ses.TOTPRequired {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"totpRequired":   true,
			"challengeToken": ses.ChallengeToken,
		})
		return
	}
	if err := h.Sessions.PutSession(r.Context(), ses); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	resp := map[string]any{"ok": true, "userId": ses.UserID}
	if ses.TOTPSetupRequired {
		resp["totpSetupRequired"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// ----- helpers -----

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": code})
}

// relayErr translates an SDK *APIError into a JSON response that
// matches ManyRows' wire format ({error: "error.code"} + same status).
// Non-API errors (network, decode) come out as 500 + "error.internalError".
func relayErr(w http.ResponseWriter, err error) {
	var apiErr *APIError
	if asAPIErr(err, &apiErr) {
		writeJSONError(w, apiErr.Status, apiErr.Code)
		return
	}
	writeJSONError(w, http.StatusInternalServerError, "error.internalError")
}

func asAPIErr(err error, target **APIError) bool {
	for e := err; e != nil; {
		if v, ok := e.(*APIError); ok {
			*target = v
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := e.(unwrapper); ok {
			e = u.Unwrap()
		} else {
			break
		}
	}
	return false
}

func redirectErr(w http.ResponseWriter, r *http.Request, base, errCode string) {
	if base == "" {
		http.Error(w, errCode, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, appendQuery(base, "error", errCode), http.StatusFound)
}

func appendQuery(base, key, value string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}
