package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

const testSecret = "whsec_test_supersecret_please_rotate"

func sign(t *testing.T, secret, ts string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func headers(ts, sig string) http.Header {
	h := http.Header{}
	if ts != "" {
		h.Set("X-Webhook-Timestamp", ts)
	}
	if sig != "" {
		h.Set("X-Webhook-Signature", sig)
	}
	return h
}

func atUnix(sec int64) func() time.Time {
	return func() time.Time { return time.Unix(sec, 0) }
}

func TestVerify_OK(t *testing.T) {
	body := []byte(`{"event":"user.created","userId":"u_1"}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := sign(t, testSecret, ts, body)

	if err := Verify(testSecret, headers(ts, sig), body); err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
}

func TestVerify_MissingTimestamp(t *testing.T) {
	body := []byte("{}")
	sig := sign(t, testSecret, "1700000000", body)
	err := Verify(testSecret, headers("", sig), body)
	if !errors.Is(err, ErrMissingTimestamp) {
		t.Fatalf("expected ErrMissingTimestamp, got %v", err)
	}
}

func TestVerify_MissingSignature(t *testing.T) {
	body := []byte("{}")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	err := Verify(testSecret, headers(ts, ""), body)
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}
}

func TestVerify_MalformedTimestamp(t *testing.T) {
	body := []byte("{}")
	sig := sign(t, testSecret, "not-a-number", body)
	err := Verify(testSecret, headers("not-a-number", sig), body)
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("expected ErrInvalidTimestamp, got %v", err)
	}
}

func TestVerify_StaleTimestamp(t *testing.T) {
	body := []byte("{}")
	// 1 hour ago — well outside the default 5-minute window.
	ts := strconv.FormatInt(1700000000, 10)
	sig := sign(t, testSecret, ts, body)

	err := Verify(testSecret, headers(ts, sig), body, VerifyOptions{
		Now: atUnix(1700000000 + 3600),
	})
	if !errors.Is(err, ErrTimestampOutOfWindow) {
		t.Fatalf("expected ErrTimestampOutOfWindow, got %v", err)
	}
}

func TestVerify_FutureTimestamp(t *testing.T) {
	body := []byte("{}")
	// 1 hour in the future.
	ts := strconv.FormatInt(1700000000+3600, 10)
	sig := sign(t, testSecret, ts, body)

	err := Verify(testSecret, headers(ts, sig), body, VerifyOptions{
		Now: atUnix(1700000000),
	})
	if !errors.Is(err, ErrTimestampOutOfWindow) {
		t.Fatalf("expected ErrTimestampOutOfWindow, got %v", err)
	}
}

func TestVerify_TamperedBody(t *testing.T) {
	original := []byte(`{"amount":1}`)
	tampered := []byte(`{"amount":1000}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := sign(t, testSecret, ts, original)

	err := Verify(testSecret, headers(ts, sig), tampered)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerify_TamperedTimestamp(t *testing.T) {
	body := []byte("{}")
	originalTS := strconv.FormatInt(time.Now().Unix(), 10)
	sig := sign(t, testSecret, originalTS, body)

	// Caller submits a different timestamp than the one signed.
	tamperedTS := strconv.FormatInt(time.Now().Unix()+1, 10)
	err := Verify(testSecret, headers(tamperedTS, sig), body)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	body := []byte("{}")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := sign(t, "different-secret", ts, body)
	err := Verify(testSecret, headers(ts, sig), body)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerify_MissingAlgorithmPrefix(t *testing.T) {
	// Server always emits "sha256=" prefix; a signature without the
	// prefix is malformed for this version.
	body := []byte("{}")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	rawHex := hex.EncodeToString(mac.Sum(nil))

	err := Verify(testSecret, headers(ts, rawHex), body)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for unprefixed sig, got %v", err)
	}
}

func TestVerify_CustomTolerance(t *testing.T) {
	body := []byte("{}")
	// 30 seconds ago — outside a 10-second tolerance.
	ts := strconv.FormatInt(1700000000, 10)
	sig := sign(t, testSecret, ts, body)

	err := Verify(testSecret, headers(ts, sig), body, VerifyOptions{
		Tolerance: 10 * time.Second,
		Now:       atUnix(1700000000 + 30),
	})
	if !errors.Is(err, ErrTimestampOutOfWindow) {
		t.Fatalf("expected ErrTimestampOutOfWindow with tight tolerance, got %v", err)
	}
}
