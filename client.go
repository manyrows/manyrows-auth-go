// Package manyrows provides a Go client for the ManyRows Server API.
package manyrows

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Client is a ManyRows Server API client.
type Client struct {
	baseURL       string // e.g. "https://app.manyrows.com"
	workspaceSlug string
	appID         string
	apiKey        string
	httpClient    *http.Client
}

// NewClient creates a new ManyRows Server API client.
func NewClient(baseURL, workspaceSlug, appID, apiKey string) *Client {
	return &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		workspaceSlug: workspaceSlug,
		appID:         appID,
		apiKey:        apiKey,
		httpClient:    &http.Client{},
	}
}

func (c *Client) apiURL(path string) string {
	return fmt.Sprintf("%s/x/%s/api/apps/%s%s", c.baseURL, c.workspaceSlug, c.appID, path)
}

func (c *Client) doGet(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("User-Agent", "manyrows-go/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("manyrows: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("manyrows: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manyrows: %s (status %d)", string(body), resp.StatusCode)
	}

	return body, nil
}

// --- Delivery ---

// ConfigItem represents a config key value.
type ConfigItem struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value any    `json:"value,omitempty"`
	IsSet bool   `json:"isSet,omitempty"` // for secrets

	// Envelope is the encrypted secret payload (set only on entries
	// under Config.Secrets, only when IsSet is true). Pass to
	// secrets.Decrypt with your workspace private key to recover the
	// JSON-encoded plaintext.
	//
	// json.RawMessage is the right shape — the envelope is opaque to
	// us; the secrets package parses + verifies the inner structure.
	Envelope json.RawMessage `json:"envelope,omitempty"`
}

// FeatureFlag represents a feature flag.
type FeatureFlag struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
}

// Delivery is the server delivery response containing config and feature flags.
type Delivery struct {
	WorkspaceID string `json:"workspaceId"`
	ProjectID   string `json:"projectId"`
	AppID       string `json:"appId"`
	UpdatedAt   string `json:"updatedAt"`
	Config      struct {
		Public  []ConfigItem `json:"public"`
		Private []ConfigItem `json:"private"`
		Secrets []ConfigItem `json:"secrets"`
	} `json:"config"`
	Flags struct {
		Client []FeatureFlag `json:"client"`
		Server []FeatureFlag `json:"server"`
	} `json:"flags"`
}

// GetDelivery returns config keys and feature flags for the app.
func (c *Client) GetDelivery() (*Delivery, error) {
	body, err := c.doGet(c.apiURL("/"))
	if err != nil {
		return nil, err
	}
	var d Delivery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("manyrows: failed to decode delivery: %w", err)
	}
	return &d, nil
}

// --- Permissions ---

// PermissionResult is the response from the check-permission endpoint.
type PermissionResult struct {
	Allowed    bool   `json:"allowed"`
	Permission string `json:"permission"`
	AccountID  string `json:"accountId"`
}

// CheckPermission checks if a user has a specific permission.
func (c *Client) CheckPermission(accountID, permission string) (*PermissionResult, error) {
	u := c.apiURL("/check-permission") + "?accountId=" + url.QueryEscape(accountID) + "&permission=" + url.QueryEscape(permission)
	body, err := c.doGet(u)
	if err != nil {
		return nil, err
	}
	var r PermissionResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("manyrows: failed to decode permission result: %w", err)
	}
	return &r, nil
}

// HasPermission is a convenience method that returns true if the user has the permission.
func (c *Client) HasPermission(accountID, permission string) (bool, error) {
	r, err := c.CheckPermission(accountID, permission)
	if err != nil {
		return false, err
	}
	return r.Allowed, nil
}

// --- Members ---

// Member represents a user with roles in the app.
type Member struct {
	UserID          string   `json:"userId"`
	Email           string   `json:"email"`
	Enabled         bool     `json:"enabled"`
	Source          string   `json:"source"`
	AddedAt         string   `json:"addedAt"`
	LastLoginAt     *string  `json:"lastLoginAt,omitempty"`
	EmailVerifiedAt *string  `json:"emailVerifiedAt,omitempty"`
	Roles           []string `json:"roles"`
}

// MembersResult is the paginated response from the members endpoint.
type MembersResult struct {
	Members  []Member `json:"members"`
	Total    int      `json:"total"`
	Page     int      `json:"page"`
	PageSize int      `json:"pageSize"`
}

// ListMembers returns paginated members for the app.
func (c *Client) ListMembers(page, pageSize int) (*MembersResult, error) {
	u := c.apiURL("/members") + "?page=" + strconv.Itoa(page) + "&pageSize=" + strconv.Itoa(pageSize)
	body, err := c.doGet(u)
	if err != nil {
		return nil, err
	}
	var r MembersResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("manyrows: failed to decode members: %w", err)
	}
	return &r, nil
}

// ListMembersByEmail returns members filtered by email substring.
func (c *Client) ListMembersByEmail(email string, page, pageSize int) (*MembersResult, error) {
	u := c.apiURL("/members") + "?email=" + url.QueryEscape(email) + "&page=" + strconv.Itoa(page) + "&pageSize=" + strconv.Itoa(pageSize)
	body, err := c.doGet(u)
	if err != nil {
		return nil, err
	}
	var r MembersResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("manyrows: failed to decode members: %w", err)
	}
	return &r, nil
}

// --- Users ---

// User represents a user looked up by ID or email.
type User struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Enabled bool   `json:"enabled"`
	Source  string `json:"source"`
}

// UserFieldValue represents a user field value.
type UserFieldValue struct {
	ID          string `json:"id"`
	UserFieldID string `json:"userFieldId"`
	Value       any    `json:"value"`
	UpdatedAt   string `json:"updatedAt"`
}

// UserResult is the response from the user lookup endpoint.
type UserResult struct {
	User        User             `json:"user"`
	Roles       []string         `json:"roles"`
	Permissions []string         `json:"permissions"`
	Fields      []UserFieldValue `json:"fields"`
}

// GetUser looks up a user by ID.
func (c *Client) GetUser(userID string) (*UserResult, error) {
	body, err := c.doGet(c.apiURL("/users") + "?id=" + url.QueryEscape(userID))
	if err != nil {
		return nil, err
	}
	var r UserResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("manyrows: failed to decode user: %w", err)
	}
	return &r, nil
}

// GetUserByEmail looks up a user by email within the app's auth scope.
func (c *Client) GetUserByEmail(email string) (*UserResult, error) {
	body, err := c.doGet(c.apiURL("/users") + "?email=" + url.QueryEscape(email))
	if err != nil {
		return nil, err
	}
	var r UserResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("manyrows: failed to decode user: %w", err)
	}
	return &r, nil
}

// --- User Fields ---

// UserField represents a user field definition.
type UserField struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	ValueType string `json:"valueType"`
	Label     string `json:"label,omitempty"`
	Status    string `json:"status"`
}

// ListUserFields returns all user field definitions for the app.
func (c *Client) ListUserFields() ([]UserField, error) {
	body, err := c.doGet(c.apiURL("/user-fields"))
	if err != nil {
		return nil, err
	}
	var r struct {
		UserFields []UserField `json:"userFields"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("manyrows: failed to decode user fields: %w", err)
	}
	return r.UserFields, nil
}
