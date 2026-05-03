package bff

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
)

// oauthCallbackResult is the input to writeOAuthCallbackResult — one
// shape covers the success / totp-required / error branches so the
// served HTML uses a single JS template that adapts based on Outcome.
type oauthCallbackResult struct {
	Outcome string // "success" | "totp" | "error"

	// success
	UserID            string
	TOTPSetupRequired bool
	RedirectSuccess   string

	// totp
	ChallengeToken string
	RedirectTOTP   string

	// error
	Error string

	// error fallback used by every branch when we have to bail out
	// (e.g. totp branch when RedirectTOTP isn't configured)
	RedirectError string
}

// writeOAuthCallbackResult serves an HTML page that handles both the
// popup-mode AppKit flow (postMessage to opener + close) AND the
// full-page redirect mode (navigate the current tab) without needing
// the caller to signal which it is. The script branches on
// `window.opener` at runtime — popups always have a non-null opener,
// full-page navigations don't.
//
// targetOrigin for the postMessage is `window.location.origin` —
// in BFF mode the popup and opener are same-origin by construction
// (both on the customer's domain), so this is safe and doesn't need
// any client-side allowlist coordination. AppKit's listener already
// filters incoming messages by the same expected origin.
//
// The cookie that ExchangeAuthCode set via Sessions.PutSession is
// already on the response — so when the opener receives the
// postMessage and reloads its data, the session is valid; for the
// full-page case the cookie is set just before the JS-driven
// navigation. Either way the user is logged in by the time the next
// HTTP request goes out.
func writeOAuthCallbackResult(w http.ResponseWriter, res oauthCallbackResult) {
	// Build the JS-side payload — what the AppKit listener will see in
	// e.data.payload. Keep the shape close to what the non-BFF
	// per-provider callbacks send (accessToken-less in BFF mode; the
	// cookie carries auth, AppKit's bff-aware handlers already cope).
	payload := map[string]any{}
	switch res.Outcome {
	case "success":
		payload["ok"] = true
		if res.UserID != "" {
			payload["userId"] = res.UserID
		}
		if res.TOTPSetupRequired {
			payload["totpSetupRequired"] = true
		}
	case "totp":
		payload["totpRequired"] = true
		payload["challengeToken"] = res.ChallengeToken
	case "error":
		payload["error"] = res.Error
	}

	status := 200
	if res.Outcome == "error" {
		status = 400
	}

	// Resolve the full-page fallback URL (used when window.opener is
	// absent, i.e. the user landed here via a non-popup flow). For
	// totp without a configured redirect, downgrade to error.
	var redirectURL string
	switch res.Outcome {
	case "success":
		redirectURL = res.RedirectSuccess
	case "totp":
		redirectURL = res.RedirectTOTP
		if redirectURL == "" {
			payload = map[string]any{"error": "totp_redirect_not_configured"}
			status = 400
			res.Outcome = "error"
			redirectURL = res.RedirectError
		} else {
			redirectURL = appendQuery(redirectURL, "challengeToken", res.ChallengeToken)
		}
	case "error":
		redirectURL = res.RedirectError
		if redirectURL != "" {
			redirectURL = appendQuery(redirectURL, "error", res.Error)
		}
	}

	payloadJSON, _ := json.Marshal(payload)
	// noFallback prints when the full-page case has no redirect target —
	// e.g. a misconfigured customer with empty OAuthErrorRedirect. Better
	// to render a readable message than a blank page.
	noFallback := html.EscapeString(string(payloadJSON))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Completing sign-in…</title></head>
<body>
<p>Completing sign-in…</p>
<script>
(function() {
  var status = %d;
  var payload = %s;
  var redirectURL = %q;
  if (window.opener) {
    try {
      window.opener.postMessage(
        { type: "manyrows-oauth-callback", status: status, payload: payload },
        window.location.origin
      );
    } catch (e) { /* ignore — opener might be closed */ }
    window.close();
    return;
  }
  if (redirectURL) {
    window.location.replace(redirectURL);
    return;
  }
  document.body.innerHTML = "<pre>" + %q + "</pre>";
})();
</script>
</body>
</html>`, status, string(payloadJSON), redirectURL, noFallback)
}
