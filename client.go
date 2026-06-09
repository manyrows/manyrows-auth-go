// Package manyrows is a typed client for the ManyRows server-to-server API.
//
// Use it from your backend to manage and authorize users. Every call is scoped
// to one app and authenticated with a workspace API key.
//
//	client, err := manyrows.New(manyrows.Options{
//		BaseURL:   "https://auth.example.com",
//		Workspace: "acme",
//		AppID:     "3f2a…",
//		APIKey:    os.Getenv("MANYROWS_API_KEY"),
//	})
//	if err != nil { /* ... */ }
//	res, err := client.CheckPermission(ctx, userID, "posts:read")
package manyrows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is the SDK version, sent as the User-Agent on every request so the
// server (and any proxy/WAF in front of it) can identify the client rather than
// treating it as an anonymous bot. Keep in sync with the released git tag.
const Version = "1.6.0"

// userAgent is sent on every request.
const userAgent = "manyrows-auth-go/" + Version

// Options configures a Client.
type Options struct {
	// BaseURL of your ManyRows host, e.g. "https://auth.example.com".
	BaseURL string
	// Workspace slug.
	Workspace string
	// AppID (uuid).
	AppID string
	// APIKey is a server API key ("mr_<prefix>_<secret>").
	APIKey string
	// HTTPClient is optional; defaults to a client with a 30s timeout.
	HTTPClient *http.Client
}

// Client talks to one app's server-to-server API.
type Client struct {
	base   string
	apiKey string
	http   *http.Client
}

// New validates opts and returns a Client.
func New(opts Options) (*Client, error) {
	switch {
	case opts.BaseURL == "":
		return nil, fmt.Errorf("manyrows: BaseURL is required")
	case opts.Workspace == "":
		return nil, fmt.Errorf("manyrows: Workspace is required")
	case opts.AppID == "":
		return nil, fmt.Errorf("manyrows: AppID is required")
	case opts.APIKey == "":
		return nil, fmt.Errorf("manyrows: APIKey is required")
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	root := strings.TrimRight(opts.BaseURL, "/")
	base := fmt.Sprintf("%s/x/%s/api/v1/apps/%s", root, url.PathEscape(opts.Workspace), url.PathEscape(opts.AppID))
	return &Client{base: base, apiKey: opts.APIKey, http: httpClient}, nil
}

// Error is returned for any non-2xx response; it carries the HTTP status and
// the API's stable error code.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("manyrows: %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("manyrows: %d %s", e.Status, e.Code)
}

// Stable API error codes (the Code field of *Error) for the org endpoints.
const (
	CodeUserNotSignedIn = "error.userNotSignedIn"
	CodeInvitePending   = "error.invitePending"
	CodeConflict        = "error.conflict"
	CodeNotFound        = "error.notFound"
)

// IsCode reports whether err is a *Error carrying the given API code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// ---- types ----

type User struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	Enabled         bool    `json:"enabled"`
	EmailVerifiedAt *string `json:"emailVerifiedAt,omitempty"`
	PasswordSetAt   *string `json:"passwordSetAt,omitempty"`
	TOTPEnabled     bool    `json:"totpEnabled"`
	Source          string  `json:"source"`
}

type UserFieldValue struct {
	ID          string          `json:"id"`
	UserID      string          `json:"userId"`
	UserFieldID string          `json:"userFieldId"`
	Value       json.RawMessage `json:"value,omitempty"`
	UpdatedAt   string          `json:"updatedAt"`
	UpdatedBy   string          `json:"updatedBy"`
}

// ServerUser is a user with their roles, permissions, and field values in this app.
type ServerUser struct {
	User        User             `json:"user"`
	Roles       []string         `json:"roles"`
	Permissions []string         `json:"permissions"`
	Fields      []UserFieldValue `json:"fields"`
}

type Member struct {
	UserID          string   `json:"userId"`
	Email           string   `json:"email"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	EmailVerifiedAt *string  `json:"emailVerifiedAt,omitempty"`
	PasswordSetAt   *string  `json:"passwordSetAt,omitempty"`
	LastLoginAt     *string  `json:"lastLoginAt,omitempty"`
	Source          string   `json:"source"`
	AddedAt         string   `json:"addedAt"`
	Roles           []string `json:"roles"`
}

type MembersList struct {
	Members  []Member `json:"members"`
	Total    int      `json:"total"`
	Page     int      `json:"page"`
	PageSize int      `json:"pageSize"`
}

// Organization is an app-scoped tenant.
type Organization struct {
	ID        string `json:"id"`
	AppID     string `json:"appId"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
}

// OrgMembership is one of a user's organizations + their tier (ListOrganizationsForUser).
type OrgMembership struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Slug    string `json:"slug"`
	OrgRole string `json:"orgRole"`
}

// OrgMember is a member of an organization. Email is populated by the member
// list/add responses; the lightweight membership gate omits it.
type OrgMember struct {
	UserID  string `json:"userId"`
	Email   string `json:"email"`
	OrgRole string `json:"orgRole"`
	Status  string `json:"status"`
}

// OrgInvite is a pending organization invitation.
type OrgInvite struct {
	ID             string  `json:"id"`
	Email          string  `json:"email"`
	OrgRole        string  `json:"orgRole"`
	Status         string  `json:"status"`
	InvitedByEmail *string `json:"invitedByEmail,omitempty"`
	CreatedAt      string  `json:"createdAt"`
	ExpiresAt      string  `json:"expiresAt"`
}

// Inputs.
type CreateOrganizationInput struct {
	Name        string
	Slug        string
	OwnerUserID string
}
type UpdateOrganizationInput struct {
	Name *string
	Slug *string
}
type AddOrgMemberInput struct {
	UserID  string
	Email   string
	OrgRole string
}
type CreateOrgInviteInput struct {
	Email           string
	OrgRole         string
	RoleIDs         []string
	InvitedByUserID string
}

type CheckPermissionResult struct {
	Allowed    bool   `json:"allowed"`
	Permission string `json:"permission"`
	AccountID  string `json:"accountId"`
}

type RoleSummary struct {
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type PermissionSummary struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type CreateUserInput struct {
	Email         string   `json:"email"`
	EmailVerified bool     `json:"emailVerified,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	// SendInvite emails the user a branded invitation after provisioning
	// (requires the app to have an App URL configured).
	SendInvite bool `json:"sendInvite,omitempty"`
}

type CreateUserResult struct {
	User    User     `json:"user"`
	Created bool     `json:"created"`
	Roles   []string `json:"roles"`
	// Invited is true when SendInvite was requested and the email was sent.
	Invited bool `json:"invited,omitempty"`
}

type UserStatus struct {
	UserID string `json:"userId"`
	Status string `json:"status"`
}

type RemoveUserResult struct {
	RemovedFromApp  bool `json:"removedFromApp"`
	IdentityDeleted bool `json:"identityDeleted"`
}

type MagicLinkResult struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expiresAt"`
}

type Session struct {
	ID         string `json:"id"`
	CreatedAt  string `json:"createdAt"`
	LastSeenAt string `json:"lastSeenAt"`
	ExpiresAt  string `json:"expiresAt"`
	UserAgent  string `json:"userAgent,omitempty"`
	IP         string `json:"ip,omitempty"`
}

type AuthLogEntry struct {
	ID            string `json:"id"`
	CreatedAt     string `json:"createdAt"`
	Event         string `json:"event"`
	Method        string `json:"method,omitempty"`
	Outcome       string `json:"outcome"`
	FailureReason string `json:"failureReason,omitempty"`
	ActorType     string `json:"actorType"`
	IP            string `json:"ip,omitempty"`
	UserAgent     string `json:"userAgent,omitempty"`
	RequestID     string `json:"requestId,omitempty"`
}

type AuthLogsPage struct {
	Logs     []AuthLogEntry `json:"logs"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
}

type Identity struct {
	Provider        string `json:"provider"`
	ProviderSubject string `json:"providerSubject,omitempty"`
	ProviderEmail   string `json:"providerEmail,omitempty"`
	CreatedAt       string `json:"createdAt"`
	LastLoginAt     string `json:"lastLoginAt"`
}

type Passkey struct {
	ID         string   `json:"id"`
	Name       string   `json:"name,omitempty"`
	Transports []string `json:"transports,omitempty"`
	CreatedAt  string   `json:"createdAt"`
	LastUsedAt string   `json:"lastUsedAt,omitempty"`
}

type Webhook struct {
	ID          string   `json:"id"`
	AppID       string   `json:"appId"`
	URL         string   `json:"url"`
	Secret      string   `json:"secret,omitempty"` // present only on create
	Events      []string `json:"events"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
	CreatedBy   string   `json:"createdBy"`
}

// WebhookInput registers a webhook.
type WebhookInput struct {
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	Description string   `json:"description,omitempty"`
}

// WebhookUpdate patches a webhook; nil fields are left unchanged.
type WebhookUpdate struct {
	URL         *string  `json:"url,omitempty"`
	Events      []string `json:"events,omitempty"`
	Status      *string  `json:"status,omitempty"`
	Description *string  `json:"description,omitempty"`
}

type UserField struct {
	ID           string `json:"id"`
	UserPoolID   string `json:"userPoolId"`
	Key          string `json:"key"`
	ValueType    string `json:"valueType"`
	Visibility   string `json:"visibility"`
	UserEditable bool   `json:"userEditable"`
	Label        string `json:"label"`
	Status       string `json:"status"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
	CreatedBy    string `json:"createdBy"`
}

type DeliveryConfigItem struct {
	Key      string          `json:"key"`
	Type     string          `json:"type"`
	Value    json.RawMessage `json:"value,omitempty"`
	IsSet    *bool           `json:"isSet,omitempty"`
	Envelope json.RawMessage `json:"envelope,omitempty"`
}

type DeliveryFlagItem struct {
	Key     string   `json:"key"`
	Enabled bool     `json:"enabled"`
	RoleIDs []string `json:"roleIds,omitempty"`
}

type Delivery struct {
	WorkspaceID string `json:"workspaceId"`
	ProductID   string `json:"productId"`
	AppID       string `json:"appId"`
	UpdatedAt   string `json:"updatedAt"`
	Config      struct {
		Public  []DeliveryConfigItem `json:"public"`
		Private []DeliveryConfigItem `json:"private"`
		Secrets []DeliveryConfigItem `json:"secrets"`
	} `json:"config"`
	Flags struct {
		Client []DeliveryFlagItem `json:"client"`
		Server []DeliveryFlagItem `json:"server"`
	} `json:"flags"`
}

// ---- Delivery ----

// GetDelivery returns all config values and feature flags for the app.
func (c *Client) GetDelivery(ctx context.Context) (*Delivery, error) {
	var out Delivery
	return &out, c.do(ctx, http.MethodGet, "/", nil, nil, &out)
}

// ---- Authorization ----

// CheckPermission reports whether a member has a permission in this app.
func (c *Client) CheckPermission(ctx context.Context, userID, permission string) (*CheckPermissionResult, error) {
	var out CheckPermissionResult
	q := url.Values{"accountId": {userID}, "permission": {permission}}
	return &out, c.do(ctx, http.MethodGet, "/check-permission", q, nil, &out)
}

// HasPermission is a convenience wrapper over CheckPermission that returns just
// the allow/deny boolean.
func (c *Client) HasPermission(ctx context.Context, userID, permission string) (bool, error) {
	res, err := c.CheckPermission(ctx, userID, permission)
	if err != nil {
		return false, err
	}
	return res.Allowed, nil
}

// ListRoles returns the product's roles, each with the permission slugs it grants.
func (c *Client) ListRoles(ctx context.Context) ([]RoleSummary, error) {
	var out struct {
		Roles []RoleSummary `json:"roles"`
	}
	return out.Roles, c.do(ctx, http.MethodGet, "/roles", nil, nil, &out)
}

// GetRole fetches one role (with its permission slugs) by slug.
func (c *Client) GetRole(ctx context.Context, slug string) (*RoleSummary, error) {
	var out RoleSummary
	return &out, c.do(ctx, http.MethodGet, "/roles/"+url.PathEscape(slug), nil, nil, &out)
}

// ListPermissions returns the product's permissions.
func (c *Client) ListPermissions(ctx context.Context) ([]PermissionSummary, error) {
	var out struct {
		Permissions []PermissionSummary `json:"permissions"`
	}
	return out.Permissions, c.do(ctx, http.MethodGet, "/permissions", nil, nil, &out)
}

// GetPermission fetches one permission by slug.
func (c *Client) GetPermission(ctx context.Context, slug string) (*PermissionSummary, error) {
	var out PermissionSummary
	return &out, c.do(ctx, http.MethodGet, "/permissions/"+url.PathEscape(slug), nil, nil, &out)
}

// CreateRole defines a new role, optionally with permission slugs.
func (c *Client) CreateRole(ctx context.Context, slug, name string, permissions []string) (*RoleSummary, error) {
	body := map[string]any{"slug": slug, "name": name}
	if permissions != nil {
		body["permissions"] = permissions
	}
	var out RoleSummary
	return &out, c.do(ctx, http.MethodPost, "/roles", nil, body, &out)
}

// UpdateRole updates a role's name and/or permissions. A nil arg leaves that
// field unchanged; a non-nil (even empty) permissions slice replaces the set.
func (c *Client) UpdateRole(ctx context.Context, slug string, name *string, permissions []string) (*RoleSummary, error) {
	body := map[string]any{}
	if name != nil {
		body["name"] = *name
	}
	if permissions != nil {
		body["permissions"] = permissions
	}
	var out RoleSummary
	return &out, c.do(ctx, http.MethodPatch, "/roles/"+url.PathEscape(slug), nil, body, &out)
}

// DeleteRole deletes a role.
func (c *Client) DeleteRole(ctx context.Context, slug string) error {
	return c.do(ctx, http.MethodDelete, "/roles/"+url.PathEscape(slug), nil, nil, nil)
}

// CreatePermission defines a new permission.
func (c *Client) CreatePermission(ctx context.Context, slug, name string) (*PermissionSummary, error) {
	body := map[string]string{"slug": slug, "name": name}
	var out PermissionSummary
	return &out, c.do(ctx, http.MethodPost, "/permissions", nil, body, &out)
}

// UpdatePermission renames a permission.
func (c *Client) UpdatePermission(ctx context.Context, slug, name string) (*PermissionSummary, error) {
	body := map[string]string{"name": name}
	var out PermissionSummary
	return &out, c.do(ctx, http.MethodPatch, "/permissions/"+url.PathEscape(slug), nil, body, &out)
}

// DeletePermission deletes a permission.
func (c *Client) DeletePermission(ctx context.Context, slug string) error {
	return c.do(ctx, http.MethodDelete, "/permissions/"+url.PathEscape(slug), nil, nil, nil)
}

// ---- Users ----

// ListUsersParams filters the member list. Zero values are omitted.
type ListUsersParams struct {
	Search   string
	Page     int
	PageSize int
}

// ListUsers lists the app's members (Search is an email substring filter).
func (c *Client) ListUsers(ctx context.Context, p ListUsersParams) (*MembersList, error) {
	q := url.Values{}
	if p.Search != "" {
		q.Set("search", p.Search)
	}
	if p.Page > 0 {
		q.Set("page", strconv.Itoa(p.Page))
	}
	if p.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(p.PageSize))
	}
	var out MembersList
	return &out, c.do(ctx, http.MethodGet, "/users", q, nil, &out)
}

// GetUserByEmail looks up a member by exact email.
func (c *Client) GetUserByEmail(ctx context.Context, email string) (*ServerUser, error) {
	var out ServerUser
	return &out, c.do(ctx, http.MethodGet, "/users", url.Values{"email": {email}}, nil, &out)
}

// GetUser fetches a member by id.
func (c *Client) GetUser(ctx context.Context, userID string) (*ServerUser, error) {
	var out ServerUser
	return &out, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID), nil, nil, &out)
}

// CreateUser provisions a user: create-or-find by email in the pool and add to
// the app. Idempotent.
func (c *Client) CreateUser(ctx context.Context, in CreateUserInput) (*CreateUserResult, error) {
	var out CreateUserResult
	return &out, c.do(ctx, http.MethodPost, "/users", nil, in, &out)
}

// BatchCreateUsersInput provisions many users at once, all with the same
// optional roles. Up to 100 emails per call.
type BatchCreateUsersInput struct {
	Emails        []string `json:"emails"`
	EmailVerified bool     `json:"emailVerified,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

// BatchUserResult is the per-email outcome of a batch provision.
type BatchUserResult struct {
	Email   string `json:"email"`
	UserID  string `json:"userId,omitempty"`
	Created bool   `json:"created"`
	Error   string `json:"error,omitempty"`
}

// BatchCreateUsers provisions many users in one call. Roles are resolved once
// (a bad slug fails the whole request); each email is reported independently,
// so one bad email doesn't sink the rest. Idempotent per email.
func (c *Client) BatchCreateUsers(ctx context.Context, in BatchCreateUsersInput) ([]BatchUserResult, error) {
	var out struct {
		Results []BatchUserResult `json:"results"`
	}
	return out.Results, c.do(ctx, http.MethodPost, "/users:batch", nil, in, &out)
}

// SetUserStatus suspends ("disabled") or re-enables ("active") a member in this app.
func (c *Client) SetUserStatus(ctx context.Context, userID, status string) (*UserStatus, error) {
	var out UserStatus
	body := map[string]string{"status": status}
	return &out, c.do(ctx, http.MethodPatch, "/users/"+url.PathEscape(userID), nil, body, &out)
}

// RemoveUser removes a member from the app; the pool identity is deleted too if
// the user is left in no other app.
func (c *Client) RemoveUser(ctx context.Context, userID string) (*RemoveUserResult, error) {
	var out RemoveUserResult
	return &out, c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID), nil, nil, &out)
}

// ReplaceUserRoles replaces a member's roles (full set of slugs; an empty slice
// clears them and revokes the user's sessions). Returns the resulting slugs.
func (c *Client) ReplaceUserRoles(ctx context.Context, userID string, roles []string) ([]string, error) {
	if roles == nil {
		roles = []string{}
	}
	var out struct {
		Roles []string `json:"roles"`
	}
	body := map[string][]string{"roles": roles}
	return out.Roles, c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/roles", nil, body, &out)
}

// AddUserRole grants one role to a member without disturbing the others
// (idempotent) and returns the resulting role slugs.
func (c *Client) AddUserRole(ctx context.Context, userID, roleSlug string) ([]string, error) {
	var out struct {
		Roles []string `json:"roles"`
	}
	path := "/users/" + url.PathEscape(userID) + "/roles/" + url.PathEscape(roleSlug)
	return out.Roles, c.do(ctx, http.MethodPost, path, nil, nil, &out)
}

// RemoveUserRole revokes one role from a member (idempotent) and returns the
// resulting role slugs.
func (c *Client) RemoveUserRole(ctx context.Context, userID, roleSlug string) ([]string, error) {
	var out struct {
		Roles []string `json:"roles"`
	}
	path := "/users/" + url.PathEscape(userID) + "/roles/" + url.PathEscape(roleSlug)
	return out.Roles, c.do(ctx, http.MethodDelete, path, nil, nil, &out)
}

// GetUserPermissions lists a member's direct permission overrides (slugs),
// separate from the permissions inherited via roles.
func (c *Client) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	var out struct {
		Permissions []string `json:"permissions"`
	}
	return out.Permissions, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/permissions", nil, nil, &out)
}

// SetUserPermissions replaces a member's direct permission overrides (full set
// of slugs) and returns the result.
func (c *Client) SetUserPermissions(ctx context.Context, userID string, permissions []string) ([]string, error) {
	if permissions == nil {
		permissions = []string{}
	}
	var out struct {
		Permissions []string `json:"permissions"`
	}
	body := map[string][]string{"permissions": permissions}
	return out.Permissions, c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/permissions", nil, body, &out)
}

// GetUserAuthLogs returns a member's authentication-event history for this app
// (newest first, paginated). Pass page/pageSize <= 0 to use the defaults.
func (c *Client) GetUserAuthLogs(ctx context.Context, userID string, page, pageSize int) (*AuthLogsPage, error) {
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		q.Set("pageSize", strconv.Itoa(pageSize))
	}
	var out AuthLogsPage
	return &out, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/auth-logs", q, nil, &out)
}

// AuthLogsParams filters the app-wide auth-log query. Zero values are omitted.
// Since/Until are RFC3339; Outcome is "success" or "failure".
type AuthLogsParams struct {
	Since    string
	Until    string
	Outcome  string
	Page     int
	PageSize int
}

// ListAuthLogs returns the app's auth-event history (all users), newest first —
// for ingesting into a SIEM/analytics pipeline (use Since/Until for incremental pulls).
func (c *Client) ListAuthLogs(ctx context.Context, p AuthLogsParams) (*AuthLogsPage, error) {
	q := url.Values{}
	if p.Since != "" {
		q.Set("since", p.Since)
	}
	if p.Until != "" {
		q.Set("until", p.Until)
	}
	if p.Outcome != "" {
		q.Set("outcome", p.Outcome)
	}
	if p.Page > 0 {
		q.Set("page", strconv.Itoa(p.Page))
	}
	if p.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(p.PageSize))
	}
	var out AuthLogsPage
	return &out, c.do(ctx, http.MethodGet, "/auth-logs", q, nil, &out)
}

// ListWebhooks lists the app's webhook subscriptions (signing secrets redacted).
func (c *Client) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	var out struct {
		Webhooks []Webhook `json:"webhooks"`
	}
	return out.Webhooks, c.do(ctx, http.MethodGet, "/webhooks", nil, nil, &out)
}

// CreateWebhook registers a webhook. The returned Webhook.Secret is populated
// only here — store it; it's redacted on every later read.
func (c *Client) CreateWebhook(ctx context.Context, in WebhookInput) (*Webhook, error) {
	var out Webhook
	return &out, c.do(ctx, http.MethodPost, "/webhooks", nil, in, &out)
}

// GetWebhook fetches one webhook (secret redacted).
func (c *Client) GetWebhook(ctx context.Context, webhookID string) (*Webhook, error) {
	var out Webhook
	return &out, c.do(ctx, http.MethodGet, "/webhooks/"+url.PathEscape(webhookID), nil, nil, &out)
}

// UpdateWebhook patches a webhook (URL, events, status, description).
func (c *Client) UpdateWebhook(ctx context.Context, webhookID string, patch WebhookUpdate) (*Webhook, error) {
	var out Webhook
	return &out, c.do(ctx, http.MethodPatch, "/webhooks/"+url.PathEscape(webhookID), nil, patch, &out)
}

// DeleteWebhook removes a webhook.
func (c *Client) DeleteWebhook(ctx context.Context, webhookID string) error {
	return c.do(ctx, http.MethodDelete, "/webhooks/"+url.PathEscape(webhookID), nil, nil, nil)
}

// RotateWebhookSecret issues a fresh signing secret; the returned Webhook.Secret
// is populated only here.
func (c *Client) RotateWebhookSecret(ctx context.Context, webhookID string) (*Webhook, error) {
	var out Webhook
	return &out, c.do(ctx, http.MethodPost, "/webhooks/"+url.PathEscape(webhookID)+"/rotate-secret", nil, nil, &out)
}

// RevokeUserSessions force-logs-out a member from this app and returns the count revoked.
func (c *Client) RevokeUserSessions(ctx context.Context, userID string) (int64, error) {
	var out struct {
		Revoked int64 `json:"revoked"`
	}
	return out.Revoked, c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/sessions", nil, nil, &out)
}

// ListUserSessions lists a member's active sessions for this app.
func (c *Client) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	var out struct {
		Sessions []Session `json:"sessions"`
	}
	return out.Sessions, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/sessions", nil, nil, &out)
}

// RevokeUserSession revokes a single session of a member.
func (c *Client) RevokeUserSession(ctx context.Context, userID, sessionID string) error {
	path := "/users/" + url.PathEscape(userID) + "/sessions/" + url.PathEscape(sessionID)
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

// SetUserPassword sets or replaces a member's password (enforced against the app's policy).
func (c *Client) SetUserPassword(ctx context.Context, userID, password string) error {
	body := map[string]string{"password": password}
	return c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/password", nil, body, nil)
}

// ClearUserPassword removes a member's password (email+password sign-in disabled until reset).
func (c *Client) ClearUserPassword(ctx context.Context, userID string) error {
	return c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/password", nil, nil, nil)
}

// SetUserEmailVerified marks a member's email verified or unverified (a
// pool-level attribute, so it applies across every app sharing the pool).
func (c *Client) SetUserEmailVerified(ctx context.Context, userID string, verified bool) error {
	body := map[string]bool{"verified": verified}
	return c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/email-verified", nil, body, nil)
}

// SetUserEnabled enables/disables a user's identity pool-wide (ban). Disabling
// blocks sign-in to every app sharing the pool and revokes the user's sessions.
func (c *Client) SetUserEnabled(ctx context.Context, userID string, enabled bool) error {
	body := map[string]bool{"enabled": enabled}
	return c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/enabled", nil, body, nil)
}

// ChangeUserEmail changes a member's email and marks it verified. Returns a
// *Error with Status 409 if the address is already in use in the pool.
func (c *Client) ChangeUserEmail(ctx context.Context, userID, email string) error {
	body := map[string]string{"email": email}
	return c.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/email", nil, body, nil)
}

// CreateMagicLink generates a one-time passwordless sign-in link for a member
// (requires the app's primary auth method to be Magic Link).
func (c *Client) CreateMagicLink(ctx context.Context, userID string, rememberMe bool) (*MagicLinkResult, error) {
	var out MagicLinkResult
	body := map[string]bool{"rememberMe": rememberMe}
	return &out, c.do(ctx, http.MethodPost, "/users/"+url.PathEscape(userID)+"/magic-link", nil, body, &out)
}

// ---- User fields ----

// ListUserFields returns the pool's user-field definitions.
func (c *Client) ListUserFields(ctx context.Context) ([]UserField, error) {
	var out struct {
		UserFields []UserField `json:"userFields"`
	}
	return out.UserFields, c.do(ctx, http.MethodGet, "/user-fields", nil, nil, &out)
}

// GetUserFieldValues returns a member's field values.
func (c *Client) GetUserFieldValues(ctx context.Context, userID string) ([]UserFieldValue, error) {
	var out struct {
		Values []UserFieldValue `json:"values"`
	}
	return out.Values, c.do(ctx, http.MethodGet, "/user-fields/users/"+url.PathEscape(userID), nil, nil, &out)
}

// SetUserFieldValue sets a member's value for a field (validated server-side
// against the field's type). value is JSON-encoded as sent.
func (c *Client) SetUserFieldValue(ctx context.Context, fieldID, userID string, value any) (*UserFieldValue, error) {
	var out struct {
		Value UserFieldValue `json:"value"`
	}
	body := map[string]any{"value": value}
	path := "/user-fields/" + url.PathEscape(fieldID) + "/users/" + url.PathEscape(userID)
	return &out.Value, c.do(ctx, http.MethodPut, path, nil, body, &out)
}

// DeleteUserFieldValue clears a member's value for a field.
func (c *Client) DeleteUserFieldValue(ctx context.Context, fieldID, userID string) error {
	path := "/user-fields/" + url.PathEscape(fieldID) + "/users/" + url.PathEscape(userID)
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

// SetConfigValue sets this app's value for a public/private config key and
// returns the stored value as raw JSON. value is JSON-encoded as sent.
func (c *Client) SetConfigValue(ctx context.Context, configKey string, value any) (json.RawMessage, error) {
	body := map[string]any{"value": value}
	var out struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	return out.Value, c.do(ctx, http.MethodPut, "/config/"+url.PathEscape(configKey), nil, body, &out)
}

// FeatureFlagOverride is this app's override for a feature flag.
type FeatureFlagOverride struct {
	Enabled bool     `json:"enabled"`
	Roles   []string `json:"roles"`
	Status  string   `json:"status"`
}

// GetConfigValue reads this app's value for a config key as raw JSON. Returns a
// *Error with Status 404 if no value is set, or 400 for a secret key.
func (c *Client) GetConfigValue(ctx context.Context, configKey string) (json.RawMessage, error) {
	var out struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	return out.Value, c.do(ctx, http.MethodGet, "/config/"+url.PathEscape(configKey), nil, nil, &out)
}

// GetFeatureFlagOverride reads this app's override for a flag. Returns a *Error
// with Status 404 if no override is set.
func (c *Client) GetFeatureFlagOverride(ctx context.Context, flagKey string) (*FeatureFlagOverride, error) {
	var out FeatureFlagOverride
	return &out, c.do(ctx, http.MethodGet, "/features/"+url.PathEscape(flagKey), nil, nil, &out)
}

// DeleteConfigValue clears this app's value for a config key.
func (c *Client) DeleteConfigValue(ctx context.Context, configKey string) error {
	return c.do(ctx, http.MethodDelete, "/config/"+url.PathEscape(configKey), nil, nil, nil)
}

// SetFeatureFlagOverride sets this app's override for a feature flag, optionally
// targeting a set of role slugs (nil/empty applies to everyone), and returns the
// resulting override.
func (c *Client) SetFeatureFlagOverride(ctx context.Context, flagKey string, enabled bool, roles []string) (*FeatureFlagOverride, error) {
	body := map[string]any{"enabled": enabled}
	if roles != nil {
		body["roles"] = roles
	}
	var out FeatureFlagOverride
	return &out, c.do(ctx, http.MethodPut, "/features/"+url.PathEscape(flagKey), nil, body, &out)
}

// ClearFeatureFlagOverride clears this app's override for a flag (falls back to default).
func (c *Client) ClearFeatureFlagOverride(ctx context.Context, flagKey string) error {
	return c.do(ctx, http.MethodDelete, "/features/"+url.PathEscape(flagKey), nil, nil, nil)
}

// ---- config-key & feature-flag DEFINITIONS (the schema; values/overrides above) ----

type ConfigKey struct {
	Key         string `json:"key"`
	Exposure    string `json:"exposure"`
	ValueType   string `json:"valueType"`
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
}

type FeatureFlag struct {
	Key            string `json:"key"`
	Scope          string `json:"scope"`
	DefaultEnabled bool   `json:"defaultEnabled"`
	Status         string `json:"status"`
	Description    string `json:"description,omitempty"`
}

// ConfigKeyInput defines a config key. Exposure is public|private|secret;
// ValueType is string|int|decimal|bool (+ []) | json.
type ConfigKeyInput struct {
	Key         string `json:"key"`
	Exposure    string `json:"exposure"`
	ValueType   string `json:"valueType"`
	Description string `json:"description,omitempty"`
}

// ConfigKeyUpdate patches a config key; nil fields are left unchanged.
type ConfigKeyUpdate struct {
	Description *string `json:"description,omitempty"`
	Exposure    *string `json:"exposure,omitempty"`
	ValueType   *string `json:"valueType,omitempty"`
	Status      *string `json:"status,omitempty"`
}

// FeatureFlagInput defines a feature flag. Scope is server|client.
type FeatureFlagInput struct {
	Key            string `json:"key"`
	Scope          string `json:"scope"`
	DefaultEnabled bool   `json:"defaultEnabled,omitempty"`
	Description    string `json:"description,omitempty"`
}

// FeatureFlagUpdate patches a feature flag; nil fields are left unchanged.
type FeatureFlagUpdate struct {
	Description    *string `json:"description,omitempty"`
	Scope          *string `json:"scope,omitempty"`
	DefaultEnabled *bool   `json:"defaultEnabled,omitempty"`
	Status         *string `json:"status,omitempty"`
}

// CreateConfigKey defines a config key.
func (c *Client) CreateConfigKey(ctx context.Context, in ConfigKeyInput) (*ConfigKey, error) {
	var out ConfigKey
	return &out, c.do(ctx, http.MethodPost, "/config-keys", nil, in, &out)
}

// UpdateConfigKey updates a config key's metadata.
func (c *Client) UpdateConfigKey(ctx context.Context, key string, patch ConfigKeyUpdate) (*ConfigKey, error) {
	var out ConfigKey
	return &out, c.do(ctx, http.MethodPatch, "/config-keys/"+url.PathEscape(key), nil, patch, &out)
}

// DeleteConfigKey deletes a config key and its per-app values.
func (c *Client) DeleteConfigKey(ctx context.Context, key string) error {
	return c.do(ctx, http.MethodDelete, "/config-keys/"+url.PathEscape(key), nil, nil, nil)
}

// CreateFeatureFlag defines a feature flag.
func (c *Client) CreateFeatureFlag(ctx context.Context, in FeatureFlagInput) (*FeatureFlag, error) {
	var out FeatureFlag
	return &out, c.do(ctx, http.MethodPost, "/feature-flags", nil, in, &out)
}

// UpdateFeatureFlag updates a feature flag's metadata.
func (c *Client) UpdateFeatureFlag(ctx context.Context, key string, patch FeatureFlagUpdate) (*FeatureFlag, error) {
	var out FeatureFlag
	return &out, c.do(ctx, http.MethodPatch, "/feature-flags/"+url.PathEscape(key), nil, patch, &out)
}

// DeleteFeatureFlag deletes a feature flag and its per-app overrides.
func (c *Client) DeleteFeatureFlag(ctx context.Context, key string) error {
	return c.do(ctx, http.MethodDelete, "/feature-flags/"+url.PathEscape(key), nil, nil, nil)
}

// ListConfigKeys lists the product's config-key definitions.
func (c *Client) ListConfigKeys(ctx context.Context) ([]ConfigKey, error) {
	var out struct {
		ConfigKeys []ConfigKey `json:"configKeys"`
	}
	return out.ConfigKeys, c.do(ctx, http.MethodGet, "/config-keys", nil, nil, &out)
}

// GetConfigKey fetches one config-key definition by key.
func (c *Client) GetConfigKey(ctx context.Context, key string) (*ConfigKey, error) {
	var out ConfigKey
	return &out, c.do(ctx, http.MethodGet, "/config-keys/"+url.PathEscape(key), nil, nil, &out)
}

// ListFeatureFlags lists the product's feature-flag definitions.
func (c *Client) ListFeatureFlags(ctx context.Context) ([]FeatureFlag, error) {
	var out struct {
		FeatureFlags []FeatureFlag `json:"featureFlags"`
	}
	return out.FeatureFlags, c.do(ctx, http.MethodGet, "/feature-flags", nil, nil, &out)
}

// GetFeatureFlag fetches one feature-flag definition by key.
func (c *Client) GetFeatureFlag(ctx context.Context, key string) (*FeatureFlag, error) {
	var out FeatureFlag
	return &out, c.do(ctx, http.MethodGet, "/feature-flags/"+url.PathEscape(key), nil, nil, &out)
}

// ResetUserTOTP disables a member's 2FA (for a user who lost their authenticator).
func (c *Client) ResetUserTOTP(ctx context.Context, userID string) error {
	return c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/totp", nil, nil, nil)
}

// UnlockUser clears a failed-login lockout on a member.
func (c *Client) UnlockUser(ctx context.Context, userID string) error {
	return c.do(ctx, http.MethodPost, "/users/"+url.PathEscape(userID)+"/unlock", nil, nil, nil)
}

// ListUserIdentities returns a member's linked SSO/OAuth identities.
func (c *Client) ListUserIdentities(ctx context.Context, userID string) ([]Identity, error) {
	var out struct {
		Identities []Identity `json:"identities"`
	}
	return out.Identities, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/identities", nil, nil, &out)
}

// DeleteUserIdentity unlinks a member's SSO identity for a provider (e.g. "google").
func (c *Client) DeleteUserIdentity(ctx context.Context, userID, provider string) error {
	return c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/identities/"+url.PathEscape(provider), nil, nil, nil)
}

// ListUserPasskeys returns a member's passkeys (WebAuthn credentials) for this app.
func (c *Client) ListUserPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	var out struct {
		Passkeys []Passkey `json:"passkeys"`
	}
	return out.Passkeys, c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/passkeys", nil, nil, &out)
}

// DeleteUserPasskey removes one of a member's passkeys.
func (c *Client) DeleteUserPasskey(ctx context.Context, userID, passkeyID string) error {
	return c.do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/passkeys/"+url.PathEscape(passkeyID), nil, nil, nil)
}

// ---- internal ----

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("manyrows: encode request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return fmt.Errorf("manyrows: build request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("manyrows: request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		apiErr := &Error{Status: res.StatusCode, Code: fmt.Sprintf("http_%d", res.StatusCode), Message: http.StatusText(res.StatusCode)}
		var parsed struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if data, _ := io.ReadAll(res.Body); len(data) > 0 {
			if json.Unmarshal(data, &parsed) == nil {
				if parsed.Error != "" {
					apiErr.Code = parsed.Error
				}
				if parsed.Message != "" {
					apiErr.Message = parsed.Message
				}
			}
		}
		return apiErr
	}

	if out == nil || res.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("manyrows: decode response: %w", err)
	}
	return nil
}

// ---- Organizations ----

func (c *Client) CreateOrganization(ctx context.Context, in CreateOrganizationInput) (*Organization, error) {
	body := map[string]any{"name": in.Name, "ownerUserId": in.OwnerUserID}
	if in.Slug != "" {
		body["slug"] = in.Slug
	}
	var out Organization
	return &out, c.do(ctx, http.MethodPost, "/organizations", nil, body, &out)
}

func (c *Client) ListOrganizationsForUser(ctx context.Context, userID string) ([]OrgMembership, error) {
	var out struct {
		Organizations []OrgMembership `json:"organizations"`
	}
	return out.Organizations, c.do(ctx, http.MethodGet, "/organizations", url.Values{"userId": {userID}}, nil, &out)
}

func (c *Client) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	var out Organization
	return &out, c.do(ctx, http.MethodGet, "/organizations/"+url.PathEscape(orgID), nil, nil, &out)
}

func (c *Client) UpdateOrganization(ctx context.Context, orgID string, in UpdateOrganizationInput) (*Organization, error) {
	body := map[string]any{}
	if in.Name != nil {
		body["name"] = *in.Name
	}
	if in.Slug != nil {
		body["slug"] = *in.Slug
	}
	var out Organization
	return &out, c.do(ctx, http.MethodPatch, "/organizations/"+url.PathEscape(orgID), nil, body, &out)
}

// DeleteOrganization hard-deletes an org. The auth server enforces owner-only
// deletion: actorUserID names the acting end-user, who must be an active owner
// of the org, or the call is rejected (400 if empty, 403 if not an owner).
func (c *Client) DeleteOrganization(ctx context.Context, orgID, actorUserID string) error {
	q := url.Values{"actorUserId": {actorUserID}}
	return c.do(ctx, http.MethodDelete, "/organizations/"+url.PathEscape(orgID), q, nil, nil)
}

// ---- Organization members ----

func (c *Client) ListOrganizationMembers(ctx context.Context, orgID string) ([]OrgMember, error) {
	var out struct {
		Members []OrgMember `json:"members"`
	}
	return out.Members, c.do(ctx, http.MethodGet, "/organizations/"+url.PathEscape(orgID)+"/members", nil, nil, &out)
}

func (c *Client) GetOrganizationMember(ctx context.Context, orgID, userID string) (*OrgMember, error) {
	var out OrgMember
	return &out, c.do(ctx, http.MethodGet, "/organizations/"+url.PathEscape(orgID)+"/members/"+url.PathEscape(userID), nil, nil, &out)
}

func (c *Client) AddOrganizationMember(ctx context.Context, orgID string, in AddOrgMemberInput) (*OrgMember, error) {
	body := map[string]any{"orgRole": in.OrgRole}
	if in.UserID != "" {
		body["userId"] = in.UserID
	}
	if in.Email != "" {
		body["email"] = in.Email
	}
	var out OrgMember
	return &out, c.do(ctx, http.MethodPost, "/organizations/"+url.PathEscape(orgID)+"/members", nil, body, &out)
}

func (c *Client) SetOrganizationMemberRole(ctx context.Context, orgID, userID, orgRole string) error {
	return c.do(ctx, http.MethodPatch, "/organizations/"+url.PathEscape(orgID)+"/members/"+url.PathEscape(userID), nil, map[string]string{"orgRole": orgRole}, nil)
}

func (c *Client) RemoveOrganizationMember(ctx context.Context, orgID, userID string) error {
	return c.do(ctx, http.MethodDelete, "/organizations/"+url.PathEscape(orgID)+"/members/"+url.PathEscape(userID), nil, nil, nil)
}

// ---- Organization invites ----

func (c *Client) CreateOrganizationInvite(ctx context.Context, orgID string, in CreateOrgInviteInput) (*OrgInvite, error) {
	body := map[string]any{"email": in.Email}
	if in.OrgRole != "" {
		body["orgRole"] = in.OrgRole
	}
	if len(in.RoleIDs) > 0 {
		body["roleIds"] = in.RoleIDs
	}
	if in.InvitedByUserID != "" {
		body["invitedByUserId"] = in.InvitedByUserID
	}
	var out OrgInvite
	return &out, c.do(ctx, http.MethodPost, "/organizations/"+url.PathEscape(orgID)+"/invites", nil, body, &out)
}

func (c *Client) ListOrganizationInvites(ctx context.Context, orgID string) ([]OrgInvite, error) {
	var out struct {
		Invites []OrgInvite `json:"invites"`
	}
	return out.Invites, c.do(ctx, http.MethodGet, "/organizations/"+url.PathEscape(orgID)+"/invites", nil, nil, &out)
}

func (c *Client) RevokeOrganizationInvite(ctx context.Context, orgID, inviteID string) error {
	return c.do(ctx, http.MethodDelete, "/organizations/"+url.PathEscape(orgID)+"/invites/"+url.PathEscape(inviteID), nil, nil, nil)
}
