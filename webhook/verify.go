// Package webhook provides a verification helper for ManyRows
// outbound webhook deliveries.
//
// Usage in a customer's webhook receiver:
//
//	body, err := io.ReadAll(r.Body)
//	if err != nil { /* 400 */ }
//	if err := webhook.Verify(secret, r.Header, body); err != nil {
//	    http.Error(w, "invalid signature", http.StatusUnauthorized)
//	    return
//	}
//	// signature good — parse body and process
//
// IMPORTANT: read the body BEFORE verifying. The HMAC covers the
// raw bytes exactly as transmitted; re-serializing parsed JSON will
// almost always change byte-level whitespace and break the check.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerTimestamp = "X-Webhook-Timestamp"
	headerSignature = "X-Webhook-Signature"
	signaturePrefix = "sha256="
	defaultTolerance = 5 * time.Minute
)

// Sentinel errors. Callers can switch on these to surface specific
// failure reasons (e.g. log "bad signature" vs "stale timestamp"
// differently). All four indicate the webhook should be rejected.
var (
	ErrMissingTimestamp     = errors.New("manyrows webhook: missing X-Webhook-Timestamp header")
	ErrMissingSignature     = errors.New("manyrows webhook: missing X-Webhook-Signature header")
	ErrInvalidTimestamp     = errors.New("manyrows webhook: malformed X-Webhook-Timestamp value")
	ErrTimestampOutOfWindow = errors.New("manyrows webhook: timestamp outside accepted window")
	ErrInvalidSignature     = errors.New("manyrows webhook: signature mismatch")
)

// VerifyOptions tunes Verify. The zero value uses sensible defaults
// (5-minute tolerance, time.Now).
type VerifyOptions struct {
	// Tolerance accepts timestamps within ±tolerance of Now. Default
	// 5 minutes. Tighten if you have very strict clock-sync; loosen
	// only if you trust the receiver's clock might drift more than
	// that — 5 minutes already covers typical NTP-synced systems.
	Tolerance time.Duration

	// Now overrides time.Now. Test hook; leave nil in production.
	Now func() time.Time
}

// Verify checks the HMAC-SHA256 signature and timestamp on an
// inbound webhook delivery from ManyRows. Returns nil iff the
// delivery is authentic AND its timestamp is within the configured
// window.
//
// The signature is computed over the canonical string
// "<timestamp>.<body>" so a replay of an old delivery is detectable
// by the timestamp check even if the body itself is unchanged.
func Verify(secret string, headers http.Header, body []byte, opts ...VerifyOptions) error {
	var opt VerifyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.Tolerance <= 0 {
		opt.Tolerance = defaultTolerance
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}

	tsRaw := strings.TrimSpace(headers.Get(headerTimestamp))
	if tsRaw == "" {
		return ErrMissingTimestamp
	}
	sigRaw := strings.TrimSpace(headers.Get(headerSignature))
	if sigRaw == "" {
		return ErrMissingSignature
	}

	tsUnix, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return ErrInvalidTimestamp
	}
	delta := now().Unix() - tsUnix
	tolSec := int64(opt.Tolerance / time.Second)
	if delta < -tolSec || delta > tolSec {
		return ErrTimestampOutOfWindow
	}

	// Strip the "sha256=" algorithm prefix. We only support sha256
	// for now; future versions may add v2 with a different prefix.
	sigHex := sigRaw
	if strings.HasPrefix(sigHex, signaturePrefix) {
		sigHex = sigHex[len(signaturePrefix):]
	} else {
		return ErrInvalidSignature
	}
	provided, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrInvalidSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tsRaw))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := mac.Sum(nil)

	if !hmac.Equal(expected, provided) {
		return ErrInvalidSignature
	}
	return nil
}
