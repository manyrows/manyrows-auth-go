package manyrows

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, "ws", "app1", "secret-key")
	return srv, c
}

func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	c := NewClient("https://example.com/", "ws", "app1", "key")
	if c.baseURL != "https://example.com" {
		t.Fatalf("expected trailing slash trimmed, got %q", c.baseURL)
	}
}

func TestApiURL(t *testing.T) {
	c := NewClient("https://app.manyrows.com", "my-ws", "app123", "key")
	got := c.apiURL("/check-permission")
	want := "https://app.manyrows.com/x/my-ws/api/apps/app123/check-permission"
	if got != want {
		t.Fatalf("apiURL mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestDoGet_SetsAPIKey(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "ws", "app1", "my-secret")
	c.doGet(srv.URL + "/test")

	if gotKey != "my-secret" {
		t.Fatalf("expected API key %q, got %q", "my-secret", gotKey)
	}
}

func TestDoGet_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "ws", "app1", "key")
	_, err := c.doGet(srv.URL + "/test")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestGetDelivery(t *testing.T) {
	delivery := Delivery{
		WorkspaceID: "ws-1",
		ProjectID:   "proj-1",
		AppID:       "app-1",
		UpdatedAt:   "2025-01-01T00:00:00Z",
	}
	delivery.Config.Public = []ConfigItem{{Key: "site_name", Type: "string", Value: "Test"}}
	delivery.Config.Private = []ConfigItem{{Key: "db_host", Type: "string", Value: "localhost"}}
	delivery.Config.Secrets = []ConfigItem{{Key: "api_secret", Type: "string", IsSet: true}}
	delivery.Flags.Client = []FeatureFlag{{Key: "dark_mode", Enabled: true}}
	delivery.Flags.Server = []FeatureFlag{{Key: "new_pipeline", Enabled: false}}

	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(delivery)
	})

	got, err := c.GetDelivery()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.WorkspaceID != "ws-1" {
		t.Errorf("WorkspaceID = %q, want %q", got.WorkspaceID, "ws-1")
	}
	if len(got.Config.Public) != 1 || got.Config.Public[0].Key != "site_name" {
		t.Errorf("unexpected public config: %+v", got.Config.Public)
	}
	if len(got.Flags.Client) != 1 || !got.Flags.Client[0].Enabled {
		t.Errorf("unexpected client flags: %+v", got.Flags.Client)
	}
	if len(got.Flags.Server) != 1 || got.Flags.Server[0].Enabled {
		t.Errorf("unexpected server flags: %+v", got.Flags.Server)
	}
}

func TestGetDelivery_BadJSON(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	})

	_, err := c.GetDelivery()
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestCheckPermission(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("accountId") != "user-42" {
			t.Errorf("unexpected accountId: %s", r.URL.Query().Get("accountId"))
		}
		if r.URL.Query().Get("permission") != "admin.edit" {
			t.Errorf("unexpected permission: %s", r.URL.Query().Get("permission"))
		}
		json.NewEncoder(w).Encode(PermissionResult{
			Allowed:    true,
			Permission: "admin.edit",
			AccountID:  "user-42",
		})
	})

	got, err := c.CheckPermission("user-42", "admin.edit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Allowed {
		t.Error("expected Allowed=true")
	}
	if got.AccountID != "user-42" {
		t.Errorf("AccountID = %q, want %q", got.AccountID, "user-42")
	}
}

func TestHasPermission(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(PermissionResult{Allowed: false})
	})

	allowed, err := c.HasPermission("user-1", "delete")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected allowed=false")
	}
}

func TestListMembers(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			t.Errorf("unexpected page: %s", r.URL.Query().Get("page"))
		}
		if r.URL.Query().Get("pageSize") != "10" {
			t.Errorf("unexpected pageSize: %s", r.URL.Query().Get("pageSize"))
		}
		json.NewEncoder(w).Encode(MembersResult{
			Members:  []Member{{UserID: "u1", Email: "a@b.com", Enabled: true, Roles: []string{"admin"}}},
			Total:    1,
			Page:     1,
			PageSize: 10,
		})
	})

	got, err := c.ListMembers(1, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Total != 1 {
		t.Errorf("Total = %d, want 1", got.Total)
	}
	if got.Members[0].Email != "a@b.com" {
		t.Errorf("Email = %q, want %q", got.Members[0].Email, "a@b.com")
	}
}

func TestListMembersByEmail(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("email") != "test@example.com" {
			t.Errorf("unexpected email filter: %s", r.URL.Query().Get("email"))
		}
		json.NewEncoder(w).Encode(MembersResult{
			Members: []Member{{UserID: "u2", Email: "test@example.com"}},
			Total:   1, Page: 1, PageSize: 10,
		})
	})

	got, err := c.ListMembersByEmail("test@example.com", 1, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(got.Members))
	}
}

func TestGetUser(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "user-99" {
			t.Errorf("unexpected id: %s", r.URL.Query().Get("id"))
		}
		json.NewEncoder(w).Encode(UserResult{
			User:        User{ID: "user-99", Email: "u@test.com", Enabled: true, Source: "email"},
			Roles:       []string{"viewer"},
			Permissions: []string{"read"},
			Fields:      []UserFieldValue{{ID: "f1", UserFieldID: "uf1", Value: "val"}},
		})
	})

	got, err := c.GetUser("user-99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.User.ID != "user-99" {
		t.Errorf("User.ID = %q, want %q", got.User.ID, "user-99")
	}
	if len(got.Roles) != 1 || got.Roles[0] != "viewer" {
		t.Errorf("unexpected roles: %v", got.Roles)
	}
}

func TestGetUserByEmail(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("email") != "hello@world.com" {
			t.Errorf("unexpected email: %s", r.URL.Query().Get("email"))
		}
		json.NewEncoder(w).Encode(UserResult{
			User: User{ID: "user-7", Email: "hello@world.com"},
		})
	})

	got, err := c.GetUserByEmail("hello@world.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.User.Email != "hello@world.com" {
		t.Errorf("Email = %q, want %q", got.User.Email, "hello@world.com")
	}
}

func TestListUserFields(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"userFields": []UserField{
				{ID: "uf1", Key: "company", ValueType: "string", Label: "Company", Status: "active"},
				{ID: "uf2", Key: "age", ValueType: "number", Status: "active"},
			},
		})
	})

	got, err := c.ListUserFields()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(got))
	}
	if got[0].Key != "company" {
		t.Errorf("first field key = %q, want %q", got[0].Key, "company")
	}
}

func TestServerError(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})

	_, err := c.GetDelivery()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	_, err = c.CheckPermission("u", "p")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	_, err = c.ListMembers(1, 10)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}
