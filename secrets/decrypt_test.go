package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Browser-side encryption is the customer responsibility — but we
// need it for tests, since the only way to verify Decrypt is to
// round-trip a known plaintext through the same WebCrypto-equivalent
// algorithm. The implementation here mirrors
// manyrows-ui/src/project/ConfigKeys.tsx::encryptSecretValueToEnvelope.
//
// If algorithm constants ever change, update them in three places:
// the browser (ConfigKeys.tsx), Decrypt above, and this test helper.
type testEncryptOpts struct {
	plaintext   []byte
	pubJWK      []byte // workspace public ECDH P-256 JWK
	fingerprint string
}

func encryptForTest(t *testing.T, opts testEncryptOpts) []byte {
	t.Helper()

	wsPubKey, err := loadEphemeralPublicKey(opts.pubJWK)
	if err != nil {
		t.Fatalf("load workspace pub: %v", err)
	}

	curve := ecdh.P256()
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral: %v", err)
	}
	ephPub := ephPriv.PublicKey()

	shared, err := ephPriv.ECDH(wsPubKey)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	aesKey, err := hkdf.Key(sha256.New, shared, []byte(hkdfSalt), hkdfInfoFingerHdr+opts.fingerprint, 32)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand iv: %v", err)
	}
	ct := gcm.Seal(nil, iv, opts.plaintext, nil)

	// Export ephemeral public key as JWK.
	ephPubBytes := ephPub.Bytes() // 0x04 || X || Y
	if len(ephPubBytes) != 65 || ephPubBytes[0] != 0x04 {
		t.Fatalf("unexpected ephPub bytes layout")
	}
	x := ephPubBytes[1:33]
	y := ephPubBytes[33:]
	ephJWK, _ := json.Marshal(publicKeyJWK{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(x),
		Y: base64.RawURLEncoding.EncodeToString(y),
	})

	env := Envelope{
		V:                  expectedAlgVersion,
		Alg:                expectedAlgorithm,
		FingerprintSha256:  opts.fingerprint,
		EphemeralPublicJWK: ephJWK,
		IVB64:              base64.StdEncoding.EncodeToString(iv),
		CiphertextB64:      base64.StdEncoding.EncodeToString(ct),
	}
	envBytes, _ := json.Marshal(env)
	return envBytes
}

// generateTestKeypair returns a random ECDH P-256 keypair as JWKs +
// the fingerprint matching the canonical-public-JWK format the
// browser uses (sorted keys: kty, crv, x, y → SHA-256 hex).
func generateTestKeypair(t *testing.T) (privJWK, pubJWK []byte, fingerprint string) {
	t.Helper()
	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub := priv.PublicKey()

	pubBytes := pub.Bytes()
	x := pubBytes[1:33]
	y := pubBytes[33:]
	xb64 := base64.RawURLEncoding.EncodeToString(x)
	yb64 := base64.RawURLEncoding.EncodeToString(y)

	pubJWK, _ = json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256", "x": xb64, "y": yb64,
	})
	d := priv.Bytes()
	dB64 := base64.RawURLEncoding.EncodeToString(d)
	privJWK, _ = json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256", "x": xb64, "y": yb64, "d": dB64,
	})

	// Canonical pub JWK: {"crv","kty","x","y"} alphabetically.
	canon := `{"crv":"P-256","kty":"EC","x":"` + xb64 + `","y":"` + yb64 + `"}`
	sum := sha256.Sum256([]byte(canon))
	hexBuf := make([]byte, 64)
	const hexAlphabet = "0123456789abcdef"
	for i, b := range sum {
		hexBuf[i*2] = hexAlphabet[b>>4]
		hexBuf[i*2+1] = hexAlphabet[b&0x0f]
	}
	fingerprint = string(hexBuf)
	return
}

func TestDecrypt_RoundTrip_String(t *testing.T) {
	privJWK, pubJWK, fp := generateTestKeypair(t)

	// Browser stringifies the value first: JSON.stringify("hello") => `"hello"`
	plaintext := []byte(`"hello"`)
	env := encryptForTest(t, testEncryptOpts{plaintext: plaintext, pubJWK: pubJWK, fingerprint: fp})

	got, err := Decrypt(env, privJWK)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != `"hello"` {
		t.Errorf("got %q want %q", got, `"hello"`)
	}

	// Now caller-side: json.Unmarshal into a typed value.
	var v string
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v != "hello" {
		t.Errorf("typed: got %q want hello", v)
	}
}

func TestDecrypt_RoundTrip_Object(t *testing.T) {
	privJWK, pubJWK, fp := generateTestKeypair(t)

	plaintext := []byte(`{"db_url":"postgres://localhost","port":5432}`)
	env := encryptForTest(t, testEncryptOpts{plaintext: plaintext, pubJWK: pubJWK, fingerprint: fp})

	got, err := Decrypt(env, privJWK)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("got %q want %q", got, plaintext)
	}
}

func TestDecrypt_RejectsTamperedCiphertext(t *testing.T) {
	privJWK, pubJWK, fp := generateTestKeypair(t)
	env := encryptForTest(t, testEncryptOpts{
		plaintext: []byte(`"hello"`), pubJWK: pubJWK, fingerprint: fp,
	})

	// Flip a byte in ciphertextB64
	var asMap map[string]interface{}
	_ = json.Unmarshal(env, &asMap)
	ct := asMap["ciphertextB64"].(string)
	asMap["ciphertextB64"] = ct[:len(ct)-2] + "AA"
	tampered, _ := json.Marshal(asMap)

	if _, err := Decrypt(tampered, privJWK); err == nil {
		t.Fatal("expected error on tampered ciphertext")
	}
}

func TestDecrypt_RejectsWrongPrivateKey(t *testing.T) {
	_, pubJWK, fp := generateTestKeypair(t)
	env := encryptForTest(t, testEncryptOpts{
		plaintext: []byte(`"hello"`), pubJWK: pubJWK, fingerprint: fp,
	})

	// Use a DIFFERENT private key.
	otherPriv, _, _ := generateTestKeypair(t)
	if _, err := Decrypt(env, otherPriv); err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecrypt_RejectsBadFingerprint(t *testing.T) {
	privJWK, pubJWK, fp := generateTestKeypair(t)
	env := encryptForTest(t, testEncryptOpts{
		plaintext: []byte(`"hello"`), pubJWK: pubJWK, fingerprint: fp,
	})

	// Replace fingerprint — HKDF info bound to it changes, AEAD fails.
	var asMap map[string]interface{}
	_ = json.Unmarshal(env, &asMap)
	asMap["fingerprintSha256"] = strings.Repeat("a", 64)
	tampered, _ := json.Marshal(asMap)

	if _, err := Decrypt(tampered, privJWK); err == nil {
		t.Fatal("expected error when fingerprint changed (HKDF info mismatch)")
	}
}

func TestDecrypt_RejectsUnsupportedAlgorithm(t *testing.T) {
	privJWK, pubJWK, fp := generateTestKeypair(t)
	env := encryptForTest(t, testEncryptOpts{
		plaintext: []byte(`"hello"`), pubJWK: pubJWK, fingerprint: fp,
	})

	var asMap map[string]interface{}
	_ = json.Unmarshal(env, &asMap)
	asMap["alg"] = "AES-128-CBC"
	tampered, _ := json.Marshal(asMap)

	_, err := Decrypt(tampered, privJWK)
	if err == nil || !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("expected unsupported-algorithm error, got %v", err)
	}
}

func TestDecrypt_RejectsMalformedJSON(t *testing.T) {
	privJWK, _, _ := generateTestKeypair(t)
	if _, err := Decrypt([]byte("not json"), privJWK); err == nil {
		t.Fatal("expected error on malformed envelope")
	}
}
