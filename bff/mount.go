package bff

import (
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// MountProxy attaches the AppKit-authed data-call proxy at the
// standard path AppKit uses in bffMode. After this:
//
//	mux := chi.NewRouter()
//	bff.MountProxy(mux, mrClient, sessions)
//
// every browser request to /apps/{appId}/a/* (e.g. /apps/<id>/a/me/sessions,
// /apps/<id>/a/app/me) is forwarded to ManyRows /bff/proxy/<rest> with
// HTTP Basic + X-BFF-Session-ID. The /apps/{appId}/a prefix is the
// AppKit convention; customers shouldn't need to think about it.
//
// chi-specific because pulling {appId} via chi.URLParam is the only
// reasonable way to recover the dynamic prefix mid-request — net/http's
// stdlib mux strips static prefixes via http.StripPrefix but won't
// touch parameterized ones. Customers on other routers can either
// adopt chi for this one mount or wire bff.Proxy themselves with
// equivalent prefix-stripping logic.
func MountProxy(r chi.Router, client *Client, sessions *SessionManager) {
	proxy := Proxy(client, sessions)
	r.HandleFunc("/apps/{appId}/a/*", func(w http.ResponseWriter, req *http.Request) {
		appID := chi.URLParam(req, "appId")
		prefix := "/apps/" + appID + "/a"
		req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		proxy.ServeHTTP(w, req)
	})
}

// MountAppBoot attaches the public app-config proxy at /apps/{appId}
// AND the pre-login auth-route proxy at /apps/{appId}/auth/* (OAuth
// authorize calls, password reset, email-OTP request — anything the
// browser needs to hit before it has a session).
//
// AppKit in full-BFF mode treats `baseUrl = /apps/<id>` and calls
// e.g. baseUrl + "/auth/microsoft/authorize". Without these proxies
// those calls fall through to the customer's SPA fallback (200 +
// HTML), AppKit fails to parse the response, and the user sees a
// bare "Request failed." downstream.
//
// All proxied calls forward as-is to ManyRows' public
// /x/{workspaceSlug}/apps/{appId}/... surface; no session is added,
// and any incoming Cookie / Authorization is stripped (the customer's
// cookie wouldn't make sense to ManyRows, and these endpoints don't
// want session creds anyway).
//
// Cacheable in the future (the boot response is identical for every
// visitor) but for now it's one upstream call per page load. Drop a
// thin LRU in front of c.HTTP if it shows up in flame graphs.
func MountAppBoot(r chi.Router, client *Client, workspaceSlug string) {
	bootProxy := publicAppProxy(client, workspaceSlug, "")
	authProxy := publicAppProxy(client, workspaceSlug, "/auth")

	r.Get("/apps/{appId}", bootProxy)
	r.HandleFunc("/apps/{appId}/auth/*", authProxy)
}

// publicAppProxy builds an http.HandlerFunc that forwards a
// /apps/{appId}{suffixPrefix}/<rest> request to ManyRows at
// /x/{workspaceSlug}/apps/{appId}{suffixPrefix}/<rest>. Method,
// query string, and request body are preserved; hop-by-hop headers
// and session-bearing headers are stripped on both legs.
//
// suffixPrefix is the portion after {appId} that the handler is
// responsible for ("" for the bare boot endpoint, "/auth" for the
// pre-login auth surface). It's matched against the request path
// to recover the trailing wildcard.
func publicAppProxy(client *Client, workspaceSlug, suffixPrefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		appID := chi.URLParam(req, "appId")
		base := "/apps/" + appID + suffixPrefix
		rest := strings.TrimPrefix(req.URL.Path, base)
		upstream := client.BaseURL + "/x/" + workspaceSlug + "/apps/" + appID + suffixPrefix + rest
		if req.URL.RawQuery != "" {
			upstream += "?" + req.URL.RawQuery
		}

		ureq, err := http.NewRequestWithContext(req.Context(), req.Method, upstream, req.Body)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		for k, vv := range req.Header {
			ck := http.CanonicalHeaderKey(k)
			if _, hop := hopByHopHeaders[ck]; hop {
				continue
			}
			if ck == "Cookie" || ck == "Authorization" || ck == "Host" {
				continue
			}
			for _, v := range vv {
				ureq.Header.Add(k, v)
			}
		}
		resp, err := client.HTTP.Do(ureq)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
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
	}
}
