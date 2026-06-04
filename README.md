# manyrows-auth-go

Go libraries for integrating with a [ManyRows](https://manyrows.com) install.

The examples below assume a self-hosted deployment at
`https://manyrows.example.com`. Swap in whatever host your install
runs on (`http://localhost:3000` for local development, your own
domain in production).

## Install

```bash
go get github.com/manyrows/manyrows-auth-go
```

## Client

The client wraps the ManyRows server-to-server API: the full admin surface
(users, roles, permissions, sessions, passkeys, webhooks, config keys, feature
flags, auth logs, and more). Every call is scoped to one app and authenticated
with a workspace API key. Methods take a `context.Context`.

```go
import (
    "context"
    "os"

    manyrows "github.com/manyrows/manyrows-auth-go"
)

client, err := manyrows.New(manyrows.Options{
    BaseURL:   "https://manyrows.example.com",        // base URL of your install
    Workspace: "your-workspace",                      // workspace slug
    AppID:     "your-app-id",                         // app ID
    APIKey:    os.Getenv("MANYROWS_API_KEY"),         // server API key ("mr_<prefix>_<secret>")
})
if err != nil {
    // missing required option
}
```

Any non-2xx response is returned as a typed `*manyrows.Error` carrying the HTTP
status and the API's stable error code:

```go
var apiErr *manyrows.Error
if errors.As(err, &apiErr) && apiErr.Status == 404 {
    // not found
}
```

### Delivery (config + feature flags)

```go
delivery, err := client.GetDelivery(context.Background())
// delivery.Config.Public, delivery.Config.Private, delivery.Config.Secrets
// delivery.Flags.Client, delivery.Flags.Server
```

### Decrypt secrets

Secret values come back as encrypted envelopes under
`delivery.Config.Secrets[i].Envelope`. Use the `secrets` package with
your workspace private key (the JWK you downloaded when you generated
the keypair in your install's admin UI) to decrypt server-side:

```go
import (
    "encoding/json"
    "github.com/manyrows/manyrows-auth-go/secrets"
)

// Load once at startup from a secret manager / env var. Never commit it.
privateKeyJWK := []byte(os.Getenv("MANYROWS_WORKSPACE_PRIVATE_KEY"))

for _, sec := range delivery.Config.Secrets {
    if sec.IsSet == nil || !*sec.IsSet || len(sec.Envelope) == 0 {
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
the private key can decrypt. The server stores the envelope as-is
and never has access to the plaintext.

### Check permission

```go
allowed, err := client.HasPermission(ctx, userID, "posts:edit")

// Or get the full result:
result, err := client.CheckPermission(ctx, userID, "posts:edit")
// result.Allowed, result.Permission, result.AccountID
```

### User lookup

```go
// By ID
user, err := client.GetUser(ctx, userID)
// user.User.Email, user.Roles, user.Permissions, user.Fields

// By email
user, err := client.GetUserByEmail(ctx, "user@example.com")
```

### Members

```go
result, err := client.ListUsers(ctx, manyrows.ListUsersParams{Page: 1, PageSize: 50})
// result.Members, result.Total, result.Page, result.PageSize

// Filter by email substring
result, err := client.ListUsers(ctx, manyrows.ListUsersParams{Search: "alice"})
```

### Managing users

Provision, suspend, and remove members; manage their roles, permissions,
sessions, passwords, identities, and passkeys:

```go
created, err := client.CreateUser(ctx, manyrows.CreateUserInput{
    Email: "new@example.com",
    Roles: []string{"editor"},
})

roles, err := client.ReplaceUserRoles(ctx, userID, []string{"admin"})
err = client.SetUserPassword(ctx, userID, "s3cret-passphrase")
revoked, err := client.RevokeUserSessions(ctx, userID)
err = client.ResetUserTOTP(ctx, userID)
```

### Roles, permissions, config keys & feature flags

Full CRUD for the product's roles, permissions, config-key definitions, and
feature-flag definitions, plus per-app config values and flag overrides:

```go
roles, err := client.ListRoles(ctx)
perms, err := client.ListPermissions(ctx)
err = client.SetConfigValue(ctx, "max_seats", 25)
ov, err := client.SetFeatureFlagOverride(ctx, "new_billing", true, []string{"beta"})
```

### Webhooks & auth logs

```go
hook, err := client.CreateWebhook(ctx, manyrows.WebhookInput{
    URL:    "https://example.com/webhooks/manyrows",
    Events: []string{"user.created"},
})
// hook.Secret is populated only on create — store it.

page, err := client.ListAuthLogs(ctx, manyrows.AuthLogsParams{Outcome: "failure"})
```

### User fields

```go
fields, err := client.ListUserFields(ctx)
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
import "github.com/manyrows/manyrows-auth-go/auth"
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
(your install's host, e.g. `https://manyrows.example.com` or
`http://localhost:3000` in development). The `workspaceSlug` and
`appID` parameters are accepted for forward-compat (a future audience
check); they're not currently used by the verifier.

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

    manyrows "github.com/manyrows/manyrows-auth-go"
    "github.com/manyrows/manyrows-auth-go/auth"
)

func main() {
    client, err := manyrows.New(manyrows.Options{
        BaseURL:   "https://manyrows.example.com",
        Workspace: "my-workspace",
        AppID:     "my-app-id",
        APIKey:    os.Getenv("MANYROWS_API_KEY"),
    })
    if err != nil {
        panic(err)
    }

    mux := http.NewServeMux()

    // Protected routes
    protected := http.NewServeMux()
    protected.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
        userID := auth.MustUserID(r.Context())

        // Look up user details from ManyRows
        user, err := client.GetUser(r.Context(), userID)
        if err != nil {
            http.Error(w, "Failed to get user", 500)
            return
        }

        fmt.Fprintf(w, "Email: %s, Roles: %v", user.User.Email, user.Roles)
    })

    protected.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
        userID := auth.MustUserID(r.Context())

        allowed, _ := client.HasPermission(r.Context(), userID, "admin:access")
        if !allowed {
            http.Error(w, "Forbidden", 403)
            return
        }

        w.Write([]byte("Welcome, admin"))
    })

    mux.Handle("/api/", auth.Middleware(
        "https://manyrows.example.com",
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
import "github.com/manyrows/manyrows-auth-go/webhook"

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
