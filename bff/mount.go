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

// MountAppBoot attaches the public app-config proxy at /apps/{appId}.
// AppKit calls this once at boot to fetch auth methods, branding,
// OAuth client IDs, etc. — public, no session required.
//
// The handler proxies to ManyRows' public /x/{workspaceSlug}/apps/{appId}
// endpoint server-side so the browser stays same-origin in full-BFF
// mode. workspaceSlug is the customer's workspace identifier; the
// {appId} URL param matches AppKit's request directly.
//
// Cacheable in the future (the response is identical for every visitor)
// but for now it's one upstream GET per page load. Drop a thin LRU
// in front of c.HTTP if it shows up in flame graphs.
func MountAppBoot(r chi.Router, client *Client, workspaceSlug string) {
	r.Get("/apps/{appId}", func(w http.ResponseWriter, req *http.Request) {
		appID := chi.URLParam(req, "appId")
		upstream := client.BaseURL + "/x/" + workspaceSlug + "/apps/" + appID
		ureq, err := http.NewRequestWithContext(req.Context(), http.MethodGet, upstream, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Forward Accept-Language / similar pass-through headers, but
		// strip Cookie + Authorization since the public endpoint doesn't
		// want session creds and the customer's cookie wouldn't make
		// sense to ManyRows anyway.
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
	})
}
