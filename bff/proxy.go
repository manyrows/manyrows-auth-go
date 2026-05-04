package bff

import (
	"io"
	"net/http"
	"strings"
)

// hopByHopHeaders are RFC 7230 hop-by-hop headers that must NOT be
// forwarded across a proxy hop. Stripped on both inbound (browser →
// us) and outbound (us → ManyRows) directions.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// Proxy returns an http.Handler that forwards inbound requests to the
// ManyRows /bff/proxy/* subtree, attaching HTTP Basic auth and the
// user's session ID. Mount it at the prefix you want exposed to the
// browser:
//
//	mux.Handle("/api/", http.StripPrefix("/api", bff.Proxy(client, sessions)))
//
// The handler:
//   - Reads the ManyRows session ID from the scs session (set by
//     Handlers.Login etc).
//   - 401s if no session — the browser-side AppKit treats this as
//     "log in again" and bounces to the login page.
//   - Reconstructs the request: same method, body, query string, and
//     forwardable headers; URL becomes <ManyRows>/bff/proxy<path>.
//   - Adds Basic auth + X-BFF-Session-ID + X-BFF-Client-IP +
//     X-BFF-Client-User-Agent.
//   - Streams the response body straight back to the browser without
//     buffering — so file downloads / SSE / large JSON pages don't
//     bloat the customer backend's memory.
//
// On 401 from ManyRows (session expired / revoked), the handler also
// clears the cookie before relaying the 401 — so the browser's next
// page load doesn't keep sending a dead session ID.
func Proxy(c *Client, mgr *SessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := mgr.SessionIDFromContext(r.Context())
		if sessionID == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Build the upstream URL. r.URL.Path here is whatever StripPrefix
		// left behind — e.g. "/me" if the customer mounted at "/api/" and
		// the browser hit "/api/me". We tack /bff/proxy on the front.
		upstreamURL := c.BaseURL + "/bff/proxy" + r.URL.Path
		if q := r.URL.RawQuery; q != "" {
			upstreamURL += "?" + q
		}

		// Use the same context — it carries the IP/UA we set in
		// LoadAndSaveWithIPAndUA below, plus any request deadline.
		upstream, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Forward headers minus hop-by-hop and Cookie (the cookie was
		// for the customer's domain; ManyRows doesn't use it). Also
		// strip Authorization — Basic auth is set fresh below from
		// the BFF credentials, never from whatever the browser sent.
		for k, vv := range r.Header {
			if _, hop := hopByHopHeaders[http.CanonicalHeaderKey(k)]; hop {
				continue
			}
			ck := http.CanonicalHeaderKey(k)
			if ck == "Cookie" || ck == "Authorization" || ck == "Host" {
				continue
			}
			for _, v := range vv {
				upstream.Header.Add(k, v)
			}
		}
		upstream.SetBasicAuth(c.ClientID, c.ClientSecret)
		upstream.Header.Set(headerSessionID, sessionID)
		if ip := ClientIPFromContext(r.Context()); ip != "" {
			upstream.Header.Set(headerClientIP, ip)
		}
		if ua := ClientUserAgentFromContext(r.Context()); ua != "" {
			upstream.Header.Set(headerClientUA, ua)
		}

		resp, err := c.HTTP.Do(upstream)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// On 401 from ManyRows, kill the local cookie too so the
		// browser doesn't keep replaying a dead session. scs's Destroy
		// queues the Set-Cookie deletion which LoadAndSave writes when
		// the response flushes.
		if resp.StatusCode == http.StatusUnauthorized {
			_ = mgr.Destroy(r.Context())
		}

		// Copy response headers minus hop-by-hop. Set-Cookie from
		// upstream is also stripped — ManyRows doesn't speak cookies
		// to BFF callers, but defensive in case it ever does.
		for k, vv := range resp.Header {
			ck := http.CanonicalHeaderKey(k)
			if _, hop := hopByHopHeaders[ck]; hop {
				continue
			}
			if ck == "Set-Cookie" {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

// ClientIPFromRequest is the default extractor used by Handlers when
// no custom one is configured AND HandlersConfig.TrustXFF is false.
// Returns r.RemoteAddr only — does NOT trust any forwarded-IP headers.
//
// This is the safe-by-default behaviour: on a bare VPS without a
// reverse proxy that strips inbound X-Forwarded-For / X-Real-IP,
// trusting those headers lets an attacker spoof the client IP and
// bypass any per-IP rate limit ManyRows enforces. The default refuses
// to trust them; customers behind a real LB / proxy that controls
// XFF should opt in via HandlersConfig.TrustXFF: true OR install a
// custom extractor via HandlersConfig.ClientIPExtractor.
//
// Matches chi/middleware.RealIP's safe-by-default posture.
func ClientIPFromRequest(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// ClientIPFromRequestTrustingProxy is the XFF-aware extractor wired
// in when HandlersConfig.TrustXFF: true. Tries (in order):
//   - rightmost X-Forwarded-For (Heroku, most cloud LBs)
//   - X-Real-IP (nginx, some others)
//   - r.RemoteAddr (direct connection)
//
// ONLY use this on a deployment where the LB / reverse proxy strips
// or overwrites inbound X-Forwarded-For / X-Real-IP from the client.
// Otherwise an attacker can spoof these headers and forge their
// apparent IP. Customers behind Cloudflare or a custom proxy that
// uses a different header (e.g. CF-Connecting-IP) should write a
// custom extractor instead — there's no general "trust proxy headers"
// switch that's safe everywhere.
func ClientIPFromRequestTrustingProxy(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		// rightmost — closest to our edge, hardest to spoof if the
		// LB writes XFF correctly. Walk right-to-left in case of
		// multiple commas with empty fields.
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" {
				return ip
			}
		}
	}
	if rip := strings.TrimSpace(r.Header.Get("X-Real-IP")); rip != "" {
		return rip
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
