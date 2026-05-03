package bff

import "context"

// Context keys for forwarding the browser's IP and User-Agent into
// outgoing ManyRows calls. Set by the Handlers/Proxy entry points;
// read by Client.newRequest. Customers shouldn't need these directly
// unless they're driving the SDK without using its handlers.
//
// Unexported types prevent collisions with other packages' context
// values — standard Go idiom for context keys.
type clientIPKey struct{}
type clientUAKey struct{}

// WithClientIP returns ctx carrying the user's real IP. The Handlers
// call this on every inbound request after extracting the IP per
// HandlersConfig.ClientIPExtractor; subsequent Client calls forward
// the value to ManyRows in X-BFF-Client-IP. Without this, ManyRows
// rate limiters and audit logs see the customer backend's egress IP.
func WithClientIP(ctx context.Context, ip string) context.Context {
	if ip == "" {
		return ctx
	}
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIPFromContext reads the IP set by WithClientIP. Empty when not set.
func ClientIPFromContext(ctx context.Context) string {
	v, _ := ctx.Value(clientIPKey{}).(string)
	return v
}

// WithClientUserAgent returns ctx carrying the browser's User-Agent.
// Handlers set it from r.UserAgent() on every inbound request; Client
// forwards it via X-BFF-Client-User-Agent. Without it, ManyRows
// session rows and audit logs show the customer backend's HTTP-client
// UA (e.g. "Go-http-client/1.1") instead of the real browser.
func WithClientUserAgent(ctx context.Context, ua string) context.Context {
	if ua == "" {
		return ctx
	}
	return context.WithValue(ctx, clientUAKey{}, ua)
}

// ClientUserAgentFromContext reads the UA set by WithClientUserAgent.
func ClientUserAgentFromContext(ctx context.Context) string {
	v, _ := ctx.Value(clientUAKey{}).(string)
	return v
}
