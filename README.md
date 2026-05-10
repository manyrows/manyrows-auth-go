# manyrows-go

Go libraries for integrating with [ManyRows](https://manyrows.com).

## Install

```bash
go get github.com/manyrows/manyrows-go
```

## Client

The client wraps the ManyRows Server API. Requires an API key.

```go
import manyrows "github.com/manyrows/manyrows-go"

client := manyrows.NewClient(
    "https://app.manyrows.com",  // base URL
    "your-workspace",            // workspace slug
    "your-app-id",               // app ID
    "mr_a1b2c3d4_yourSecretKey", // API key
)
```

### Delivery (config + feature flags)

```go
delivery, err := client.GetDelivery()
// delivery.Config.Public, delivery.Config.Private, delivery.Config.Secrets
// delivery.Flags.Client, delivery.Flags.Server
```

### Decrypt secrets

Secret values come back as encrypted envelopes under
`delivery.Config.Secrets[i].Envelope`. Use the `secrets` package with
your workspace private key (the JWK you downloaded when you generated
the keypair in the ManyRows admin UI) to decrypt server-side:

```go
import (
    "encoding/json"
    "github.com/manyrows/manyrows-go/secrets"
)

// Load once at startup from a secret manager / env var. Never commit it.
privateKeyJWK := []byte(os.Getenv("MANYROWS_WORKSPACE_PRIVATE_KEY"))

for _, sec := range delivery.Config.Secrets {
    if !sec.IsSet || len(sec.Envelope) == 0 {
        continue
    }
    plaintext, err := secrets.Decrypt(sec.Envelope, privateKeyJWK)
    if err != nil {
        log.Fatal(err)
    }
    // plaintext is JSON-encoded — for a string secret you'll get
    // `"hello"` (with quotes). Unmarshal into the typed value:
    var v string
    _ = json.Unmarshal(plaintext, &v)
}
```

Algorithm: ECDH P-256 → HKDF-SHA256 → AES-256-GCM. The browser
encrypts with the workspace public key on save; only the holder of
the private key can decrypt. ManyRows never sees plaintext.

### Check permission

```go
allowed, err := client.HasPermission(userID, "posts:edit")

// Or get the full result:
result, err := client.CheckPermission(userID, "posts:edit")
// result.Allowed, result.Permission, result.AccountID
```

### User lookup

```go
// By ID
user, err := client.GetUser(userID)
// user.User.Email, user.Roles, user.Permissions, user.Fields

// By email
user, err := client.GetUserByEmail("user@example.com")
```

### Members

```go
result, err := client.ListMembers(0, 50)
// result.Members, result.Total, result.Page, result.PageSize

// Filter by email
result, err := client.ListMembersByEmail("alice", 0, 50)
```

### User fields

```go
fields, err := client.ListUserFields()
// fields[0].Key, fields[0].ValueType, fields[0].Label
```

## Auth Middleware

HTTP middleware that verifies the user's JWT **locally** against the
install's JWKS. Fetches `${baseURL}/.well-known/jwks.json` once on
first verify, caches the keys in-process, and refetches on a kid
mismatch — no per-request round trip to ManyRows. Falls back to the
`mr_at` HttpOnly cookie when no `Authorization: Bearer` header is
present (cookie-mode AppKit deploys).

```go
import "github.com/manyrows/manyrows-go/auth"
```

### Middleware

```go
r.Use(auth.Middleware(manyrowsBaseURL, workspaceSlug, appID))
```

The middleware accepts the JWT from either:
1. `Authorization: Bearer <jwt>` (local mode / Tier 1)
2. `mr_at` cookie (cookie-mode AppKit, when your auth host and app
   host share a registrable domain)

Set `MANYROWS_BASE_URL` to the URL the SDK should use for JWKS lookup
(e.g. `https://app.manyrows.com` or your install's custom domain).
The `workspaceSlug` and `appID` parameters are accepted for forward-
compat (a future audience check); they're not currently used by the
verifier.

### UserIDFromContext

Extracts the user ID (the JWT's `sub` claim) from the request context.
Returns `false` if not present.

```go
userID, ok := auth.UserIDFromContext(r.Context())
```

### MustUserID

Same as `UserIDFromContext` but panics if the user ID is absent. Use in handlers behind `Middleware`.

```go
userID := auth.MustUserID(r.Context())
```

### Full example

```go
package main

import (
    "fmt"
    "net/http"
    "os"

    manyrows "github.com/manyrows/manyrows-go"
    "github.com/manyrows/manyrows-go/auth"
)

func main() {
    client := manyrows.NewClient(
        "https://app.manyrows.com",
        "my-workspace",
        "my-app-id",
        os.Getenv("MANYROWS_API_KEY"),
    )

    mux := http.NewServeMux()

    // Protected routes
    protected := http.NewServeMux()
    protected.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
        userID := auth.MustUserID(r.Context())

        // Look up user details from ManyRows
        user, err := client.GetUser(userID)
        if err != nil {
            http.Error(w, "Failed to get user", 500)
            return
        }

        fmt.Fprintf(w, "Email: %s, Roles: %v", user.User.Email, user.Roles)
    })

    protected.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
        userID := auth.MustUserID(r.Context())

        allowed, _ := client.HasPermission(userID, "admin:access")
        if !allowed {
            http.Error(w, "Forbidden", 403)
            return
        }

        w.Write([]byte("Welcome, admin"))
    })

    mux.Handle("/api/", auth.Middleware(
        "https://app.manyrows.com",
        "my-workspace",
        "my-app-id",
    )(protected))

    http.ListenAndServe(":3000", mux)
}
```

## Webhook verification

ManyRows signs every outbound webhook delivery. Use the `webhook`
package to verify the signature + timestamp on your receiver:

```go
import "github.com/manyrows/manyrows-go/webhook"

http.HandleFunc("/webhooks/manyrows", func(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    if err := webhook.Verify(secret, r.Header, body); err != nil {
        http.Error(w, "invalid signature", http.StatusUnauthorized)
        return
    }
    // body is verified — parse JSON and process.
})
```

`Verify` checks both the HMAC-SHA256 signature (over `<timestamp>.<body>`)
and that the `X-Webhook-Timestamp` is within ±5 minutes of now. Pass
`webhook.VerifyOptions{Tolerance: ...}` to widen or tighten the window.

Read the request body **before** verifying — the HMAC covers the raw
bytes exactly as transmitted; re-serializing parsed JSON will change
whitespace and break the check.
