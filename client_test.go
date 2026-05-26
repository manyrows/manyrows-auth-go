package manyrows

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Options{BaseURL: srv.URL, Workspace: "acme", AppID: "app-1", APIKey: "mr_abc_secret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestCheckPermission_BuildsRequest(t *testing.T) {
	var gotPath, gotKey, gotQuery string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotKey, gotQuery = r.URL.Path, r.Header.Get("X-API-Key"), r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true, "permission": "posts:read", "accountId": "u1"})
	})

	res, err := c.CheckPermission(context.Background(), "u1", "posts:read")
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if !res.Allowed {
		t.Fatal("expected allowed=true")
	}
	if gotPath != "/x/acme/api/v1/apps/app-1/check-permission" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotKey != "mr_abc_secret" {
		t.Fatalf("X-API-Key = %q", gotKey)
	}
	if !strings.Contains(gotQuery, "accountId=u1") || !strings.Contains(gotQuery, "permission=posts") {
		t.Fatalf("query = %q", gotQuery)
	}
}

func TestHasPermission_ReturnsBool(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": false, "permission": "posts:delete", "accountId": "u1"})
	})

	allowed, err := c.HasPermission(context.Background(), "u1", "posts:delete")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if allowed {
		t.Fatal("expected allowed=false")
	}
}

func TestCreateUser_PostsBody(t *testing.T) {
	var gotMethod string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]any{"id": "u2", "email": "a@b.com"}, "created": true, "roles": []string{"editor"},
		})
	})

	res, err := c.CreateUser(context.Background(), CreateUserInput{Email: "a@b.com", Roles: []string{"editor"}})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !res.Created || res.User.ID != "u2" {
		t.Fatalf("result = %+v", res)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotBody["email"] != "a@b.com" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestNon2xx_ReturnsTypedError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "error.notFound", "message": "Not found"})
	})

	_, err := c.GetUser(context.Background(), "missing")
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *manyrows.Error, got %T: %v", err, err)
	}
	if apiErr.Status != 404 || apiErr.Code != "error.notFound" || apiErr.Message != "Not found" {
		t.Fatalf("error = %+v", apiErr)
	}
}

func TestDeleteUserFieldValue_NoContent(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/user-fields/f1/users/u1") {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.DeleteUserFieldValue(context.Background(), "f1", "u1"); err != nil {
		t.Fatalf("DeleteUserFieldValue: %v", err)
	}
}

func TestListUsers_OmitsZeroParams(t *testing.T) {
	var gotQuery string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{"members": []any{}, "total": 0, "page": 0, "pageSize": 50})
	})

	if _, err := c.ListUsers(context.Background(), ListUsersParams{Search: "ali"}); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if gotQuery != "search=ali" {
		t.Fatalf("query = %q (page/pageSize should be omitted)", gotQuery)
	}
}

func TestNew_Validation(t *testing.T) {
	if _, err := New(Options{Workspace: "a", AppID: "b", APIKey: "c"}); err == nil {
		t.Fatal("expected error for missing BaseURL")
	}
	if _, err := New(Options{BaseURL: "x", Workspace: "a", AppID: "b"}); err == nil {
		t.Fatal("expected error for missing APIKey")
	}
}