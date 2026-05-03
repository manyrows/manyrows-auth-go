// Package bff is the customer-side SDK for ManyRows full-BFF mode.
//
// In full-BFF mode the customer's backend is the ONLY thing that talks
// to ManyRows. The browser holds nothing — no tokens, no JWTs — just an
// HttpOnly session cookie set by this SDK on the customer's domain.
// On every browser→backend request, this SDK looks up the user's
// ManyRows session ID from the cookie and forwards the request to
// ManyRows /bff/proxy/* with that session ID in a header. ManyRows is
// the source of truth for sessions; this SDK is a thin proxy.
//
// Three building blocks:
//
//	bff.Client     — server-to-server calls into ManyRows /bff/*
//	bff.Handlers   — HTTP handlers for /auth/login, /auth/google/callback,
//	                 /auth/logout etc. Mount these on the customer's router.
//	bff.Proxy      — single proxy handler for everything authenticated.
//	                 Mount at /api/* and it forwards to /bff/proxy/*.
//
// The session cookie is managed by alexedwards/scs — encrypted, HttpOnly,
// SameSite=Lax by default. Configure via NewSessionManager.
package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout caps every server-to-server call from this SDK to
// ManyRows. 10s is generous — auth flows that go through Google/Apple
// can be slow but rarely take more than a few seconds. Customer code
// can override via Client.HTTP.
const DefaultTimeout = 10 * time.Second

// Header names used in the BFF↔ManyRows protocol. Must match the
// constants in manyrows-core/app/routerBFF.go and bffSessionAuth.go —
// any drift between the two repos is a wire-protocol break.
const (
	headerSessionID = "X-BFF-Session-ID"
	headerClientIP  = "X-BFF-Client-IP"
	headerClientUA  = "X-BFF-Client-User-Agent"
)

// Client is the typed entry point for server-to-server calls into
// ManyRows /bff/*. Construct once at app boot, share across goroutines
// (it's safe — http.Client and the auth fields are immutable after New).
//
// All methods that touch a user-bound session take a context.Context
// so the caller can wire deadlines / cancellation. The context is
// also where the SDK reads the per-request browser IP and User-Agent
// (set by Handlers via WithClientIP / WithClientUserAgent) so they
// can be forwarded to ManyRows. Without those, ManyRows logs and
// rate-limits attribute to the customer backend's egress IP.
type Client struct {
	// BaseURL is the ManyRows root, e.g. "https://api.manyrows.com".
	// No trailing slash; the SDK appends /bff/<path> as needed.
	BaseURL string

	// ClientID and ClientSecret are the per-app BFF Basic credentials
	// from the ManyRows admin UI (App Settings → Security → BFF).
	ClientID     string
	ClientSecret string

	// HTTP is the http.Client used for outgoing calls. Defaults to
	// &http.Client{Timeout: DefaultTimeout} on New(). Override after
	// construction to set custom transport / timeouts.
	HTTP *http.Client
}

// New constructs a Client with default HTTP settings. Trims a trailing
// slash from baseURL so callers don't have to think about it.
func New(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTP:         &http.Client{Timeout: DefaultTimeout},
	}
}

// Session is what every successful auth flow returns. The SDK stashes
// SessionID in the user's cookie and forwards it back to ManyRows on
// every subsequent /api/* request. ExpiresAt is informational — the
// cookie's MaxAge can mirror it but ManyRows is the authority on
// session lifetime; on expiry, /bff/proxy/* returns 401.
type Session struct {
	SessionID string    `json:"sessionId"`
	UserID    string    `json:"userId"`
	ExpiresAt time.Time `json:"expiresAt"`

	// TOTPRequired is set when login succeeded the password / OAuth
	// gate but the app requires a TOTP step before issuing a usable
	// session. ChallengeToken carries the opaque token the customer
	// SDK forwards to /bff/totp/verify with the user's code.
	TOTPRequired   bool   `json:"totpRequired,omitempty"`
	ChallengeToken string `json:"challengeToken,omitempty"`

	// TOTPSetupRequired is set when the app requires TOTP and the user
	// hasn't enrolled yet. The session IS issued but the customer's UI
	// should route to a setup page rather than the home page.
	TOTPSetupRequired bool `json:"totpSetupRequired,omitempty"`
}

// LoginPassword exchanges email + password for a Session. The customer
// backend calls this from its /auth/login handler with the form values
// from the browser. Returns Session.TOTPRequired = true when the user
// has TOTP enrolled — the customer's /auth/login view should then
// prompt for the code and call VerifyTOTP.
func (c *Client) LoginPassword(ctx context.Context, email, password string, rememberMe bool) (*Session, error) {
	body := map[string]any{"email": email, "password": password, "rememberMe": rememberMe}
	return c.doSessionPOST(ctx, "/bff/login", body)
}

// LoginGoogle exchanges a Google ID-token credential (the value from
// Google's Sign In button / One Tap) for a Session. Same TOTP-branching
// behaviour as LoginPassword.
func (c *Client) LoginGoogle(ctx context.Context, credential string, rememberMe bool) (*Session, error) {
	body := map[string]any{"credential": credential, "rememberMe": rememberMe}
	return c.doSessionPOST(ctx, "/bff/google", body)
}

// VerifyOTP completes the email-OTP code-verification flow for both
// "primary auth = code" sign-in AND fresh-account registration. The
// browser hands the customer's BFF (email, code, optional appId,
// rememberMe); appId presence flips ManyRows into register mode.
// Same TOTP-branching as LoginPassword.
func (c *Client) VerifyOTP(ctx context.Context, email, code, appID string, rememberMe bool) (*Session, error) {
	body := map[string]any{"email": email, "code": code, "rememberMe": rememberMe}
	if appID != "" {
		body["appId"] = appID
	}
	return c.doSessionPOST(ctx, "/bff/verify", body)
}

// PasskeyLoginBegin starts a discoverable WebAuthn login. Returns the
// raw {challengeId, publicKeyOptions} payload the browser hands to
// navigator.credentials.get. No session yet; the matching Finish call
// completes auth and sets the cookie.
func (c *Client) PasskeyLoginBegin(ctx context.Context) (json.RawMessage, error) {
	return c.doRawPOST(ctx, "/bff/passkey/login/begin", map[string]any{})
}

// PasskeyLoginFinish verifies the WebAuthn assertion the browser
// returned. Returns Session on success; the SDK Handlers.* layer puts
// the session in the cookie via completeAuth.
func (c *Client) PasskeyLoginFinish(ctx context.Context, challengeID string, response json.RawMessage, rememberMe bool) (*Session, error) {
	body := map[string]any{
		"challengeId": challengeID,
		"response":    response,
		"rememberMe":  rememberMe,
	}
	return c.doSessionPOST(ctx, "/bff/passkey/login/finish", body)
}

// VerifyTOTP completes a TOTP step-up after LoginPassword / LoginGoogle
// returned TOTPRequired = true. Pass the challengeToken from that
// response and the 6-digit code the user typed.
func (c *Client) VerifyTOTP(ctx context.Context, challengeToken, code string) (*Session, error) {
	body := map[string]any{"challengeToken": challengeToken, "code": code}
	return c.doSessionPOST(ctx, "/bff/totp/verify", body)
}

// ExchangeAuthCode swaps the one-time auth code that ManyRows sends to
// the customer's OAuth-callback URL for a Session. The redirect URI
// MUST match what the OAuth flow was started with — same protection as
// any standard OAuth code exchange.
func (c *Client) ExchangeAuthCode(ctx context.Context, code, redirectURI string) (*Session, error) {
	body := map[string]any{"code": code, "redirectUri": redirectURI}
	return c.doSessionPOST(ctx, "/bff/exchange", body)
}

// ForgotPassword starts the email-OTP password-reset flow. Returns
// nil on success — no session is issued (the user gets an email with
// a one-time code which they pair with the new password via
// ResetPassword). The same anti-enumeration shape as the underlying
// ManyRows endpoint: 200 OK regardless of whether the email exists,
// to keep it from being a user-existence oracle.
func (c *Client) ForgotPassword(ctx context.Context, email, appID string) error {
	body := map[string]any{"email": email}
	if appID != "" {
		body["appId"] = appID
	}
	return c.doVoidPOST(ctx, "/bff/forgot-password", body)
}

// ResetPassword completes the email-OTP password-reset flow. The user
// supplies the email + the one-time code from the email + a new
// password. logoutAll, when true, kills every existing session for
// the user — recommended after a password reset since a stolen
// session shouldn't survive a password change.
func (c *Client) ResetPassword(ctx context.Context, email, code, newPassword, appID string, logoutAll bool) error {
	body := map[string]any{
		"email":       email,
		"code":        code,
		"newPassword": newPassword,
		"logoutAll":   logoutAll,
	}
	if appID != "" {
		body["appId"] = appID
	}
	return c.doVoidPOST(ctx, "/bff/reset-password", body)
}

// doVoidPOST is the shared shape for endpoints that succeed with 200
// + no body (forgot-password, reset-password). Decodes the standard
// {error: "..."} body on non-200 into an APIError.
func (c *Client) doVoidPOST(ctx context.Context, path string, body any) error {
	req, err := c.newRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeAPIError(resp)
	}
	return nil
}

// Logout revokes the named session in ManyRows. Idempotent — calling
// twice with the same sessionID returns nil both times. The SDK's
// Handlers.Logout calls this then clears the cookie; customers who
// implement custom logout flows can call Logout directly.
func (c *Client) Logout(ctx context.Context, sessionID string) error {
	body := map[string]any{"sessionId": sessionID}
	req, err := c.newRequest(ctx, http.MethodPost, "/bff/logout", body)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bff/logout: %s", resp.Status)
	}
	return nil
}

// doRawPOST is the shared shape for endpoints whose JSON response is
// pass-through to the browser (e.g. WebAuthn challenge payloads). The
// SDK doesn't model the body — callers forward it untouched.
func (c *Client) doRawPOST(ctx context.Context, path string, body any) (json.RawMessage, error) {
	req, err := c.newRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, decodeAPIError(resp)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read raw response: %w", err)
	}
	return raw, nil
}

// doSessionPOST is the shared shape for the four auth endpoints that
// return a Session. Decodes the standard {sessionId, userId, expiresAt}
// payload; ManyRows error responses come back as JSON {error: "..."}
// which we surface as a typed error.
func (c *Client) doSessionPOST(ctx context.Context, path string, body any) (*Session, error) {
	req, err := c.newRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, decodeAPIError(resp)
	}

	var s Session
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("decode session response: %w", err)
	}
	return &s, nil
}

// newRequest builds an http.Request bound to ctx with HTTP Basic auth
// and (when present in ctx) the X-BFF-Client-IP / X-BFF-Client-User-Agent
// headers. Body is JSON-encoded; pass nil to send no body.
func (c *Client) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	if ip := ClientIPFromContext(ctx); ip != "" {
		req.Header.Set(headerClientIP, ip)
	}
	if ua := ClientUserAgentFromContext(ctx); ua != "" {
		req.Header.Set(headerClientUA, ua)
	}
	return req, nil
}

// APIError is the typed error returned when ManyRows responds with
// 4xx / 5xx. Code is the i18n-style error key (e.g. "error.invalidCredentials");
// Message is the language-localized human-readable string ManyRows
// writes alongside it. The handler layer surfaces both to the browser
// so AppKit's UI gets the translated message, not the raw code.
type APIError struct {
	Status  int
	Code    string
	Message string
	Body    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("manyrows: %s (HTTP %d)", e.Code, e.Status)
	}
	return fmt.Sprintf("manyrows: HTTP %d", e.Status)
}

// IsUnauthorized is a convenience for the most common branch — an
// expired session, wrong password, etc. all surface as 401.
func (e *APIError) IsUnauthorized() bool { return e.Status == http.StatusUnauthorized }

func decodeAPIError(resp *http.Response) error {
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 0 {
		_ = json.Unmarshal(body, &payload)
	}
	return &APIError{Status: resp.StatusCode, Code: payload.Error, Message: payload.Message, Body: string(body)}
}

// Sentinel for the (rare) case where a Session was nil-returned for
// non-error reasons. Callers can errors.Is() against this.
var ErrNoSession = errors.New("manyrows: no session returned")
