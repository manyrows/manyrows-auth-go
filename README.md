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

HTTP middleware that validates bearer tokens by calling the ManyRows `/a/app/me` endpoint.

```go
import "github.com/manyrows/manyrows-go/auth"
```

### Middleware

```go
r.Use(auth.Middleware(manyrowsBaseURL, workspaceSlug, appID))
```

### UserIDFromContext

Extracts the user ID from the request context. Returns `false` if not present.

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
