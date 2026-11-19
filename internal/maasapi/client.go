package maasapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	baseURL       string
	tenant        string
	client        *http.Client
	strictKeyList bool
}

// TLSOptions controls verification for HTTPS MaaS deployments. The default is
// standard system-root verification; CAFile supports an internal CA, and
// InsecureSkipVerify is an explicit operator opt-in for self-signed setups.
type TLSOptions struct {
	CAFile             string
	InsecureSkipVerify bool
}

type ClientOptions struct {
	TLSOptions
	FollowRedirects bool
	StrictKeyList   bool
	// UseEnvProxy routes requests through the proxy named by HTTP_PROXY,
	// HTTPS_PROXY, and NO_PROXY. Login validation opts in (it historically
	// ran on http.DefaultTransport, which reads those variables); clients
	// that leave it unset connect directly, so cluster traffic to the
	// in-cluster maas-api never detours through an environment proxy.
	UseEnvProxy bool
}

type APIKeyResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Key            string `json:"key,omitempty"`
	Username       string `json:"username"`
	Subscription   string `json:"subscription"`
	Tenant         string `json:"tenant"`
	Status         string `json:"status"`
	CreationDate   string `json:"creationDate,omitempty"`
	ExpirationDate string `json:"expirationDate,omitempty"`
	LastUsedAt     string `json:"lastUsedAt,omitempty"`
}

type SearchResult struct {
	Object  string           `json:"object"`
	Data    []APIKeyResponse `json:"data"`
	HasMore bool             `json:"has_more"`
}

// NewClient preserves the legacy transport defaults — TLS verification
// skipped, redirects followed, no environment proxy — and exists for tests
// that stub the MaaS upstream.
//
// Deprecated: production code must use NewClientWithOptions so the deployment
// mode controls TLS verification (cluster keeps the legacy defaults, standalone
// verifies with system roots) and proxy use (login validation opts into the
// HTTP_PROXY/HTTPS_PROXY environment; key clients connect directly, except in
// standalone mode where they may reach MaaS only through a proxy); do not
// reach for this constructor outside tests.
func NewClient(baseURL, tenant string) *Client {
	client := newHTTPClient(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, true, false)
	return &Client{
		baseURL: baseURL,
		tenant:  tenant,
		client:  client,
	}
}

func NewClientWithOptions(baseURL, tenant string, options ClientOptions) (*Client, error) {
	httpClient, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &Client{baseURL: baseURL, tenant: tenant, client: httpClient, strictKeyList: options.StrictKeyList}, nil
}

func NewHTTPClient(options ClientOptions) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if options.TLSOptions.InsecureSkipVerify && options.TLSOptions.CAFile != "" {
		return nil, fmt.Errorf("CA file and insecure skip verify are mutually exclusive")
	}
	if options.TLSOptions.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	} else if options.TLSOptions.CAFile != "" {
		certificate, err := os.ReadFile(options.TLSOptions.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read MaaS CA bundle: %w", err)
		}
		// Augment the system roots instead of replacing them: a bundle that
		// carries only the internal MaaS CA must not silently break
		// verification of publicly-trusted certificates. SystemCertPool can
		// fail on platforms without a system bundle; fall back to a private
		// pool there so the explicit bundle still works.
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(certificate) {
			return nil, fmt.Errorf("MaaS CA bundle contains no PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}
	return newHTTPClient(tlsConfig, options.FollowRedirects, options.UseEnvProxy), nil
}

func newHTTPClient(tlsConfig *tls.Config, followRedirects, useEnvProxy bool) *http.Client {
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	if useEnvProxy {
		// Login validation historically ran on http.DefaultTransport, which
		// reads HTTPS_PROXY and NO_PROXY; keep that support for deployments
		// that reach MaaS only through a proxy. Clients that do not opt in
		// connect directly — the behavior before standalone management
		// existed — so cluster traffic to the in-cluster maas-api never
		// detours through an environment proxy.
		transport.Proxy = http.ProxyFromEnvironment
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	// With redirects enabled, leave CheckRedirect unset so the standard
	// client applies its 10-hop redirect limit: a self-redirecting upstream
	// would otherwise loop until the timeout. When redirects are disabled,
	// return the response as-is without following it.
	if !followRedirects {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

// CreateKeyRequest is the self-service key shape. ExpiresIn is a Go duration
// string ("2160h"); an empty value means the MaaS deployment default.
type CreateKeyRequest struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Subscription string            `json:"subscription,omitempty"`
	ExpiresIn    string            `json:"expiresIn,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
}

func (c *Client) CreateAPIKey(ctx context.Context, username, group, keyName string) (*APIKeyResponse, error) {
	return c.CreateUserAPIKey(ctx, username, group, CreateKeyRequest{Name: keyName})
}

// CreateUserAPIKey mints a key for one user with optional expiry and labels.
// The identity headers are the trusted-header contract described in the
// Atlas handoff; the caller must be a server-side handler, never a browser.
// ErrUnknownCreateOutcome marks a 2xx create response whose body could not be
// decoded: the key may exist without a record, so callers must not report a
// definitive rejection.
var ErrUnknownCreateOutcome = errors.New("key create outcome unknown")

func (c *Client) CreateUserAPIKey(ctx context.Context, username, group string, req CreateKeyRequest) (*APIKeyResponse, error) {
	username = strings.TrimSpace(username)
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/api-keys", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-MaaS-Username", username)
	groupJSON, err := json.Marshal([]string{group})
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("X-MaaS-Group", string(groupJSON))
	httpReq.Header.Set("X-MaaS-Tenant", c.tenant)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		// The request may have been dispatched before the connection failed,
		// so the key could exist: mark the outcome unknown, not a rejection.
		return nil, fmt.Errorf("%w: maas-api request failed: %v", ErrUnknownCreateOutcome, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	// A gateway timeout or bad gateway may be returned after the upstream
	// committed the key (the gateway failed on the response), so they are
	// unknown outcomes, not definitive rejections.
	if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusGatewayTimeout {
		return nil, fmt.Errorf("%w: maas-api key create returned status %d", ErrUnknownCreateOutcome, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		// Never put the upstream response body in an error: handlers log errors,
		// and MaaS bodies can echo request context or key material.
		return nil, fmt.Errorf("maas-api key create failed with status %d", resp.StatusCode)
	}

	var result APIKeyResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("%w: failed to parse create response: %v", ErrUnknownCreateOutcome, err)
	}
	// MaaS intentionally returns the one-time secret from create, but some
	// versions omit metadata that is only populated by the subsequent list
	// representation. Complete only fields this request knows authoritatively
	// so create and list expose a consistent resource without a second MaaS
	// round trip. Never overwrite richer metadata if MaaS starts returning it.
	if result.Username == "" {
		result.Username = username
	}
	if result.Tenant == "" {
		result.Tenant = c.tenant
	}
	if result.Status == "" {
		result.Status = "active"
	}
	return &result, nil
}

// ListUserAPIKeys lists a user's own keys by presenting that username to
// MaaS, which scopes non-admin searches to the caller. Pages are walked until
// MaaS reports no more results.
func (c *Client) ListUserAPIKeys(ctx context.Context, username, group string) ([]APIKeyResponse, error) {
	username = strings.TrimSpace(username)
	if username == "" || group == "" {
		return nil, fmt.Errorf("maas-api key list requires a username and group")
	}
	groupJSON, err := json.Marshal([]string{group})
	if err != nil {
		return nil, err
	}
	const pageSize = 100
	keys := []APIKeyResponse{}
	for offset := 0; offset <= 10*pageSize; offset += pageSize {
		body, err := json.Marshal(map[string]any{
			"filters":    map[string]any{"username": username},
			"pagination": map[string]int{"limit": pageSize, "offset": offset},
		})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/api-keys/search", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-MaaS-Username", username)
		req.Header.Set("X-MaaS-Group", string(groupJSON))
		req.Header.Set("X-MaaS-Tenant", c.tenant)
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("maas-api key list request failed: %w", err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= http.StatusBadRequest {
			return nil, fmt.Errorf("maas-api key list failed with status %d", resp.StatusCode)
		}
		var page SearchResult
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("failed to parse key list: %w", err)
		}
		keys = append(keys, page.Data...)
		if !page.HasMore {
			return keys, nil
		}
	}
	if c.strictKeyList {
		// Refuse rather than return a silently partial list: standalone callers
		// use this to prove key ownership and pick revocation targets.
		return nil, fmt.Errorf("maas-api key list exceeded %d keys", 11*pageSize)
	}
	return keys, nil
}

// OwnsKey reports whether keyID belongs to username, walking the key-list
// pages and stopping as soon as the key is found. A walk cut short by the page
// limit without finding the key is an error — an incomplete search is
// inconclusive, never proof of absence — so a caller revoking one known key is
// not blocked by a very large key inventory.
func (c *Client) OwnsKey(ctx context.Context, username, group, keyID string) (bool, error) {
	username = strings.TrimSpace(username)
	keyID = strings.TrimSpace(keyID)
	if username == "" || group == "" || keyID == "" {
		return false, fmt.Errorf("maas-api key ownership check requires a username, group, and key id")
	}
	groupJSON, err := json.Marshal([]string{group})
	if err != nil {
		return false, err
	}
	const pageSize = 100
	for offset := 0; offset <= 10*pageSize; offset += pageSize {
		body, err := json.Marshal(map[string]any{
			"filters":    map[string]any{"username": username},
			"pagination": map[string]int{"limit": pageSize, "offset": offset},
		})
		if err != nil {
			return false, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/api-keys/search", bytes.NewReader(body))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-MaaS-Username", username)
		req.Header.Set("X-MaaS-Group", string(groupJSON))
		req.Header.Set("X-MaaS-Tenant", c.tenant)
		resp, err := c.client.Do(req)
		if err != nil {
			return false, fmt.Errorf("maas-api key list request failed: %w", err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= http.StatusBadRequest {
			return false, fmt.Errorf("maas-api key list failed with status %d", resp.StatusCode)
		}
		var page SearchResult
		if err := json.Unmarshal(data, &page); err != nil {
			return false, fmt.Errorf("failed to parse key list: %w", err)
		}
		for _, key := range page.Data {
			if key.ID == keyID && strings.EqualFold(key.Username, username) {
				return true, nil
			}
		}
		if !page.HasMore {
			return false, nil
		}
	}
	return false, fmt.Errorf("maas-api key ownership search exceeded %d keys", 11*pageSize)
}

// RevokeUserAPIKey revokes one key as its owner and returns the MaaS status.
// MaaS answers 404 for keys the presented username does not own.
func (c *Client) RevokeUserAPIKey(ctx context.Context, keyID, username, group string) (int, error) {
	username = strings.TrimSpace(username)
	keyID = strings.TrimSpace(keyID)
	if username == "" || group == "" || keyID == "" {
		return 0, fmt.Errorf("maas-api key revoke requires a key id, username, and group")
	}
	groupJSON, err := json.Marshal([]string{group})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/api-keys/"+url.PathEscape(keyID), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-MaaS-Username", username)
	req.Header.Set("X-MaaS-Group", string(groupJSON))
	req.Header.Set("X-MaaS-Tenant", c.tenant)
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("maas-api key revoke request failed: %w", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func (c *Client) SearchAPIKeys(ctx context.Context, username string, groups []string) (*SearchResult, error) {
	searchBody := map[string]any{}
	if username != "" {
		searchBody["username"] = username
	}
	body, _ := json.Marshal(searchBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/api-keys/search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// maas-api's auth middleware requires a non-empty X-MaaS-Group on every
	// v1 call: it scopes the internal token it mints for the request and
	// 500s (AUTH_FAILURE) without one. Fail locally with a message that
	// names the real problem instead of shipping a doomed request.
	if len(groups) == 0 {
		return nil, fmt.Errorf("maas-api search: no groups to scope the request — check the MaaSSubscription groups")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MaaS-Username", "admin")
	req.Header.Set("X-MaaS-Tenant", c.tenant)
	groupJSON, _ := json.Marshal(groups)
	req.Header.Set("X-MaaS-Group", string(groupJSON))
	if token := saToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maas-api request failed: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	slog.Info("maas-api search response", "status", resp.StatusCode)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("maas-api key search failed with status %d", resp.StatusCode)
	}

	var result SearchResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

func (c *Client) RevokeAPIKey(ctx context.Context, keyID string, groups []string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/api-keys/"+keyID, nil)
	if err != nil {
		return err
	}
	// See SearchAPIKeys: the group header is mandatory on every v1 call.
	if len(groups) == 0 {
		return fmt.Errorf("maas-api revoke: no groups to scope the request — check the MaaSSubscription groups")
	}
	req.Header.Set("X-MaaS-Username", "admin")
	req.Header.Set("X-MaaS-Tenant", c.tenant)
	groupJSON, _ := json.Marshal(groups)
	req.Header.Set("X-MaaS-Group", string(groupJSON))
	if token := saToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("maas-api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("maas-api key revoke failed with status %d", resp.StatusCode)
	}
	return nil
}

func saToken() string {
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (c *Client) RevokeAllUserAPIKeys(ctx context.Context, username, group string, dryRun bool) (int, bool, error) {
	if strings.TrimSpace(username) == "" || group == "" {
		return 0, false, fmt.Errorf("username and group required")
	}
	body, err := json.Marshal(map[string]any{"username": username, "dryRun": dryRun})
	if err != nil {
		return 0, false, err
	}
	groups, err := json.Marshal([]string{group})
	if err != nil {
		return 0, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/api-keys/bulk-revoke", bytes.NewReader(body))
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MaaS-Username", username)
	req.Header.Set("X-MaaS-Group", string(groups))
	req.Header.Set("X-MaaS-Tenant", c.tenant)
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	// Match RevokeAPIKey: any 2xx means the revocation was accepted. A
	// bodyless success (e.g. 204) reports no count; the count is then unknown,
	// not zero — the revocation is accepted but the number is unrecoverable.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return 0, false, fmt.Errorf("key revocation returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Count *int `json:"revokedCount"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, false, nil
		}
		return 0, false, err
	}
	if result.Count == nil || *result.Count < 0 {
		return 0, false, fmt.Errorf("invalid key count")
	}
	return *result.Count, true, nil
}
