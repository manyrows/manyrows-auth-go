// Package secrets decrypts ManyRows config-secret envelopes using the
// workspace's private ECDH key.
//
// Usage:
//
//	import (
//	    "encoding/json"
//	    manyrows "github.com/manyrows/manyrows-go"
//	    "github.com/manyrows/manyrows-go/secrets"
//	)
//
//	// Load your workspace private key once at startup. It's the JWK
//	// you exported when you generated the keypair in the ManyRows
//	// admin UI. Stash it in a secret manager or env var; never check
//	// it into source control.
//	var privateKeyJWK = []byte(`{"kty":"EC","crv":"P-256","x":"...","y":"...","d":"..."}`)
//
//	delivery, _ := client.GetDelivery(ctx)
//	for _, sec := range delivery.Config.Secrets {
//	    if sec.IsSet == nil || !*sec.IsSet || len(sec.Envelope) == 0 {
//	        continue
//	    }
//	    plaintext, err := secrets.Decrypt(sec.Envelope, privateKeyJWK)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    // plaintext is the JSON-encoded value the browser stored.
//	    // For a string secret, plaintext == `"hello"` (with quotes).
//	    var v string
//	    _ = json.Unmarshal(plaintext, &v)
//	}
//
// Algorithm: ECDH P-256 → HKDF-SHA256 (salt "manyrows:secrets:v1",
// info "workspace-fingerprint:<hex>") → AES-256-GCM. Mirrors the
// browser-side encrypt path in manyrows-ui's ConfigKeys page; if the
// algorithm constants ever change there, update them here too.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// Mirrored exactly from manyrows-ui/src/project/ConfigKeys.tsx:
	//   salt: utf8Bytes("manyrows:secrets:v1")
	//   info: utf8Bytes(`workspace-fingerprint:${fingerprintSha256}`)
	hkdfSalt           = "manyrows:secrets:v1"
	hkdfInfoFingerHdr  = "workspace-fingerprint:"
	expectedAlgorithm  = "ECDH-P256+HKDF-SHA256+AES-256-GCM"
	expectedAlgVersion = 1
)

// Envelope is the on-the-wire shape produced by the browser at
// secret-save time. The Server API delivery returns one of these
// (as raw JSON) per secret entry under `delivery.config.secrets[].envelope`.
type Envelope struct {
	V                   int             `json:"v"`
	Alg                 string          `json:"alg"`
	FingerprintSha256   string          `json:"fingerprintSha256"`
	EphemeralPublicJWK  json.RawMessage `json:"ephemeralPublicKeyJwk"`
	IVB64               string          `json:"ivB64"`
	CiphertextB64       string          `json:"ciphertextB64"`
}

// PrivateKeyJWK is the customer's private ECDH P-256 JWK (the one
// downloaded when the workspace key was generated in the admin UI).
// Only the fields needed for decryption are typed.
type privateKeyJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

type publicKeyJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Decrypt verifies the envelope, performs the ECDH+HKDF+AES-GCM
// ceremony, and returns the JSON-encoded plaintext exactly as the
// browser stored it (i.e. for a string-typed secret you'll get
// `"hello"` with the surrounding quotes — pass it to json.Unmarshal
// to recover the typed value).
//
// `envelope` is the raw JSON from `delivery.config.secrets[].envelope`.
// `privateKeyJSON` is the customer's private JWK (`{"kty":"EC","crv":"P-256","x":"...","y":"...","d":"..."}`).
//
// Returns an error if any of the following are off: malformed
// envelope, mismatched algorithm version, base64 decode failure,
// missing/garbled key material, GCM authentication failure (which
// covers both ciphertext tamper and wrong-key cases).
func Decrypt(envelope []byte, privateKeyJSON []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("manyrows secrets: malformed envelope: %w", err)
	}
	if env.V != expectedAlgVersion {
		return nil, fmt.Errorf("manyrows secrets: unsupported envelope version %d", env.V)
	}
	if env.Alg != expectedAlgorithm {
		return nil, fmt.Errorf("manyrows secrets: unsupported algorithm %q", env.Alg)
	}
	if env.FingerprintSha256 == "" {
		return nil, errors.New("manyrows secrets: missing fingerprintSha256")
	}

	priv, err := loadPrivateKey(privateKeyJSON)
	if err != nil {
		return nil, fmt.Errorf("manyrows secrets: load private key: %w", err)
	}

	ephPub, err := loadEphemeralPublicKey(env.EphemeralPublicJWK)
	if err != nil {
		return nil, fmt.Errorf("manyrows secrets: load ephemeral public key: %w", err)
	}

	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("manyrows secrets: ECDH derive: %w", err)
	}

	aesKey, err := hkdf.Key(sha256.New, shared, []byte(hkdfSalt), hkdfInfoFingerHdr+env.FingerprintSha256, 32)
	if err != nil {
		return nil, fmt.Errorf("manyrows secrets: HKDF: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(env.IVB64)
	if err != nil || len(iv) < 12 {
		return nil, errors.New("manyrows secrets: ivB64 invalid")
	}
	ct, err := base64.StdEncoding.DecodeString(env.CiphertextB64)
	if err != nil || len(ct) == 0 {
		return nil, errors.New("manyrows secrets: ciphertextB64 invalid")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("manyrows secrets: AES new: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, fmt.Errorf("manyrows secrets: GCM init: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		// Wrong key, tampered ciphertext, or fingerprint mismatch all
		// land here. Don't leak which.
		return nil, errors.New("manyrows secrets: decrypt failed (signature mismatch or wrong key)")
	}
	return plaintext, nil
}

func loadPrivateKey(raw []byte) (*ecdh.PrivateKey, error) {
	var jwk privateKeyJWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("parse JWK: %w", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, fmt.Errorf("expected EC P-256 JWK, got kty=%q crv=%q", jwk.Kty, jwk.Crv)
	}
	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("decode d: %w", err)
	}
	// crypto/ecdh wants the raw 32-byte scalar — pad if shorter.
	if len(d) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(d):], d)
		d = padded
	}
	curve := ecdh.P256()
	return curve.NewPrivateKey(d)
}

func loadEphemeralPublicKey(raw json.RawMessage) (*ecdh.PublicKey, error) {
	var jwk publicKeyJWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("parse ephemeral JWK: %w", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, fmt.Errorf("expected EC P-256 JWK, got kty=%q crv=%q", jwk.Kty, jwk.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	// Pad to the curve's field size (32 bytes for P-256).
	const fieldBytes = 32
	if len(x) < fieldBytes {
		px := make([]byte, fieldBytes)
		copy(px[fieldBytes-len(x):], x)
		x = px
	}
	if len(y) < fieldBytes {
		py := make([]byte, fieldBytes)
		copy(py[fieldBytes-len(y):], y)
		y = py
	}
	// Uncompressed-point format: 0x04 || X || Y (SEC 1).
	point := append([]byte{0x04}, append(x, y...)...)
	curve := ecdh.P256()
	pub, err := curve.NewPublicKey(point)
	if err != nil {
		return nil, fmt.Errorf("not on P-256: %w", err)
	}
	return pub, nil
}

