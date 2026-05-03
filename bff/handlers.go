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

// Router is the minimal surface Mount needs from the customer's
// router. *http.ServeMux satisfies it; so does chi.Mux. Customers
// using gorilla/mux or any other router can either implement this
// interface or wire the handlers manually.
type Router interface {
	HandleFunc(pattern string, handler http.HandlerFunc)
}

// Mount wires the standard auth routes onto the given router.
// Equivalent to wiring each HandlerFunc by hand:
//
//	r.HandleFunc("/auth/login",          h.Login)
//	r.HandleFunc("/auth/google",         h.LoginGoogle)
//	r.HandleFunc("/auth/totp/verify",    h.VerifyTOTP)
//	r.HandleFunc("/auth/oauth/callback", h.OAuthCallback)
//	r.HandleFunc("/auth/logout",         h.Logout)
//
// Customers wanting more control (different paths, extra middleware
// per route) should skip Mount and wire the methods directly.
func (h *Handlers) Mount(r Router) {
	r.HandleFunc("/auth/login", h.Login)
	r.HandleFunc("/auth/google", h.LoginGoogle)
	r.HandleFunc("/auth/verify", h.VerifyOTP)
	r.HandleFunc("/auth/totp/verify", h.VerifyTOTP)
	r.HandleFunc("/auth/oauth/callback", h.OAuthCallback)
	r.HandleFunc("/auth/logout", h.Logout)
	r.HandleFunc("/auth/forgot-password", h.ForgotPassword)
	r.HandleFunc("/auth/reset-password", h.ResetPassword)
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

// VerifyOTP handles POST /auth/verify with JSON body
// {email, code, appId?, rememberMe}. Used for both fresh-account
// registration verification AND ongoing OTP-as-primary sign-in.
// Same response shape as Login (totpRequired branch lands the user
// on the TOTP screen; otherwise sets the cookie).
func (h *Handlers) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Email      string `json:"email"`
		Code       string `json:"code"`
		AppID      string `json:"appId"`
		RememberMe bool   `json:"rememberMe"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "error.badRequest")
		return
	}
	ses, err := h.Client.VerifyOTP(r.Context(), body.Email, body.Code, body.AppID, body.RememberMe)
	if err != nil {
		relayErr(w, err)
		return
	}
	h.completeAuth(w, r, ses)
}

// ForgotPassword handles POST /auth/forgot-password with body
// {email, appId}. Public — no session required. Returns {ok:true}
// on success regardless of whether the email exists (anti-enumeration).
func (h *Handlers) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Email string `json:"email"`
		AppID string `json:"appId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "error.badRequest")
		return
	}
	if err := h.Client.ForgotPassword(r.Context(), body.Email, body.AppID); err != nil {
		relayErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ResetPassword handles POST /auth/reset-password with body
// {email, code, newPassword, appId, logoutAll}. Public — completes
// the email-OTP reset flow. No session is issued on success; the
// user logs in normally afterward.
func (h *Handlers) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
		AppID       string `json:"appId"`
		LogoutAll   bool   `json:"logoutAll"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "error.badRequest")
		return
	}
	if err := h.Client.ResetPassword(r.Context(), body.Email, body.Code, body.NewPassword, body.AppID, body.LogoutAll); err != nil {
		relayErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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
// GitHub) login.
//
// Adaptive response: serves an HTML page that postMessages to
// window.opener (popup-mode, when AppKit's popup-based OAuth flow is
// used) OR navigates the current tab to the configured success / error
// / totp redirect URI (full-page mode). The HTML decides at runtime
// based on whether window.opener is present, so the same handler
// covers both cases without any signaling from the caller.
//
// In all branches the cookie is written via Set-Cookie on the HTML
// response itself, so popup callers come back to the opener with the
// session already valid (since opener and popup are same-origin in
// BFF mode by construction). For full-page callers the cookie lands
// before the navigation that follows.
func (h *Handlers) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errCode := strings.TrimSpace(q.Get("error")); errCode != "" {
		writeOAuthCallbackResult(w, oauthCallbackResult{
			Outcome:       "error",
			Error:         errCode,
			RedirectError: h.Cfg.OAuthErrorRedirect,
		})
		return
	}
	code := strings.TrimSpace(q.Get("code"))
	if code == "" {
		writeOAuthCallbackResult(w, oauthCallbackResult{
			Outcome:       "error",
			Error:         "missing_code",
			RedirectError: h.Cfg.OAuthErrorRedirect,
		})
		return
	}

	ses, err := h.Client.ExchangeAuthCode(r.Context(), code, h.Cfg.OAuthRedirectURI)
	if err != nil {
		var apiErr *APIError
		errCode := "exchange_failed"
		if asAPIErr(err, &apiErr) && apiErr.Code != "" {
			errCode = apiErr.Code
		}
		writeOAuthCallbackResult(w, oauthCallbackResult{
			Outcome:       "error",
			Error:         errCode,
			RedirectError: h.Cfg.OAuthErrorRedirect,
		})
		return
	}

	if ses.TOTPRequired {
		writeOAuthCallbackResult(w, oauthCallbackResult{
			Outcome:        "totp",
			ChallengeToken: ses.ChallengeToken,
			RedirectTOTP:   h.Cfg.OAuthTOTPRedirect,
			RedirectError:  h.Cfg.OAuthErrorRedirect,
		})
		return
	}

	if err := h.Sessions.PutSession(r.Context(), ses); err != nil {
		writeOAuthCallbackResult(w, oauthCallbackResult{
			Outcome:       "error",
			Error:         "session_store_failed",
			RedirectError: h.Cfg.OAuthErrorRedirect,
		})
		return
	}

	writeOAuthCallbackResult(w, oauthCallbackResult{
		Outcome:           "success",
		UserID:            ses.UserID,
		TOTPSetupRequired: ses.TOTPSetupRequired,
		RedirectSuccess:   h.Cfg.OAuthSuccessRedirect,
	})
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

// writeJSONErrorWithMessage forwards both the code AND the localized
// message — needed for AppKit's error UI which prefers the message
// over the raw code.
func writeJSONErrorWithMessage(w http.ResponseWriter, status int, code, message string) {
	body := map[string]any{"error": code}
	if message != "" {
		body["message"] = message
	}
	writeJSON(w, status, body)
}

// relayErr translates an SDK *APIError into a JSON response that
// matches ManyRows' wire format ({error, message} + same status).
// Non-API errors (network, decode) come out as 500 + "error.internalError".
func relayErr(w http.ResponseWriter, err error) {
	var apiErr *APIError
	if asAPIErr(err, &apiErr) {
		writeJSONErrorWithMessage(w, apiErr.Status, apiErr.Code, apiErr.Message)
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
