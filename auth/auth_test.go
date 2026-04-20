package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserIDFromContext_Missing(t *testing.T) {
	id, ok := UserIDFromContext(context.Background())
	if ok {
		t.Errorf("expected ok=false, got true with id=%q", id)
	}
}

func TestUserIDFromContext_Empty(t *testing.T) {
	ctx := context.WithValue(context.Background(), userIDKey, "")
	id, ok := UserIDFromContext(ctx)
	if ok {
		t.Errorf("expected ok=false for empty string, got true with id=%q", id)
	}
}

func TestUserIDFromContext_Present(t *testing.T) {
	ctx := context.WithValue(context.Background(), userIDKey, "user-42")
	id, ok := UserIDFromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if id != "user-42" {
		t.Errorf("id = %q, want %q", id, "user-42")
	}
}

func TestMustUserID_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	MustUserID(context.Background())
}

func TestMustUserID_Returns(t *testing.T) {
	ctx := context.WithValue(context.Background(), userIDKey, "user-7")
	id := MustUserID(ctx)
	if id != "user-7" {
		t.Errorf("id = %q, want %q", id, "user-7")
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"Basic abc", ""},
		{"Bearer abc123", "abc123"},
		{"Bearer  spaced ", "spaced"},
		{" Bearer tok ", "tok"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		if tt.header != "" {
			r.Header.Set("Authorization", tt.header)
		}
		got := bearerToken(r)
		if got != tt.want {
			t.Errorf("bearerToken(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

// meServer creates a test server that mimics the /a/me endpoint.
func meServer(t *testing.T, wantToken string, userID string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := bearerToken(r)
		if got != wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		json.NewEncoder(w).Encode(meResponse{User: struct {
			ID string `json:"id"`
		}{ID: userID}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMiddleware_NoToken(t *testing.T) {
	meSrv := meServer(t, "valid", "u1", http.StatusOK)
	mw := Middleware(meSrv.URL, "ws", "app1")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called without token")
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	meSrv := meServer(t, "valid-token", "u1", http.StatusOK)
	mw := Middleware(meSrv.URL, "ws", "app1")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called with invalid token")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_ValidToken(t *testing.T) {
	meSrv := meServer(t, "good-token", "user-55", http.StatusOK)
	mw := Middleware(meSrv.URL, "ws", "app1")

	var gotID string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := UserIDFromContext(r.Context())
		if !ok {
			t.Fatal("expected user ID in context")
		}
		gotID = id
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if gotID != "user-55" {
		t.Errorf("user ID = %q, want %q", gotID, "user-55")
	}
}

func TestMiddleware_MeEndpointDown(t *testing.T) {
	// Server that always returns 500
	meSrv := meServer(t, "tok", "u1", http.StatusInternalServerError)
	mw := Middleware(meSrv.URL, "ws", "app1")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called when /me fails")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestResolveUser_EmptyID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(meResponse{})
	}))
	t.Cleanup(srv.Close)

	_, err := resolveUser(srv.URL, "token")
	if err == nil {
		t.Fatal("expected error for empty user ID")
	}
}

func TestResolveUser_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)

	_, err := resolveUser(srv.URL, "token")
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestResolveUser_SetsUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		json.NewEncoder(w).Encode(meResponse{User: struct {
			ID string `json:"id"`
		}{ID: "u1"}})
	}))
	t.Cleanup(srv.Close)

	if _, err := resolveUser(srv.URL, "token"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotUA == "" || gotUA == "Go-http-client/1.1" {
		t.Errorf("User-Agent should be set to a custom value, got %q", gotUA)
	}
}
