package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type contextKey string

const userIDKey contextKey = "userID"

// meResponse is the relevant subset of the /a/me response.
type meResponse struct {
	User struct {
		ID string `json:"id"`
	} `json:"user"`
}

// UserIDFromContext extracts the manyrows user ID from the request context.
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDKey).(string)
	return id, ok && id != ""
}

// MustUserID extracts the user ID from context, panicking if absent.
// Only use in handlers behind auth Middleware, which guarantees the ID is set.
func MustUserID(ctx context.Context) string {
	id, ok := UserIDFromContext(ctx)
	if !ok {
		panic("auth: MustUserID called without authenticated context")
	}
	return id
}

// Middleware verifies the user's bearer token by calling the manyrows /a/me endpoint
// and stores the user ID in the request context.
func Middleware(manyrowsBaseURL, workspaceSlug, appID string) func(http.Handler) http.Handler {
	meURL := fmt.Sprintf("%s/x/%s/apps/%s/a/me", manyrowsBaseURL, workspaceSlug, appID)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			userID, err := resolveUser(meURL, token)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

func resolveUser(meURL, token string) (string, error) {
	req, err := http.NewRequest("GET", meURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("manyrows request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("manyrows returned %d", resp.StatusCode)
	}

	var me meResponse
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	if me.User.ID == "" {
		return "", fmt.Errorf("empty user id")
	}
	return me.User.ID, nil
}
