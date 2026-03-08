package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/turnkeystaffing/go-opentelemetry"
)

// OAuthTokenCacheConfig configures the OAuth client_credentials token cache.
// Per P3 (hardening): this config is separate from AuditConfig and HTTPWriterConfig — different concern.
type OAuthTokenCacheConfig struct {
	ClientID     string        // OAuth client ID (required)
	ClientSecret string        // OAuth client secret (required)
	TokenURL     string        // Auth server token endpoint URL (required, e.g. "https://auth.example.com/oauth/token")
	Scope        string        // OAuth scope to request (optional, e.g. "audit:write")
	HTTPTimeout  time.Duration // HTTP request timeout for token fetches (default: 10s)
}

// DefaultOAuthTokenCacheConfig returns an OAuthTokenCacheConfig with sensible defaults.
// ClientID, ClientSecret, and TokenURL must be set by the caller.
func DefaultOAuthTokenCacheConfig() OAuthTokenCacheConfig {
	return OAuthTokenCacheConfig{
		HTTPTimeout: 10 * time.Second,
	}
}

// Validate checks the OAuthTokenCacheConfig for errors.
// Zero/negative HTTPTimeout is clamped to 10s default.
func (c *OAuthTokenCacheConfig) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("oauth token cache: client ID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("oauth token cache: client secret is required")
	}
	if c.TokenURL == "" {
		return fmt.Errorf("oauth token cache: token URL is required")
	}

	parsed, err := url.Parse(c.TokenURL)
	if err != nil {
		return fmt.Errorf("oauth token cache: invalid token URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("oauth token cache: token URL scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("oauth token cache: token URL must include a host")
	}

	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 10 * time.Second
	}

	return nil
}

// oauthTokenResponse is the wire format for OAuth 2.1 token response (RFC 6749 Section 5.1).
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// OAuthTokenCache implements TokenProvider with in-memory caching, proactive refresh at 80% lifetime,
// and single-flight guard for async refresh. Thread-safe via sync.RWMutex.
type OAuthTokenCache struct {
	client       *http.Client
	clientID     string
	clientSecret string
	tokenURL     string
	scope        string
	httpTimeout  time.Duration
	log          *slog.Logger

	mu          sync.RWMutex
	accessToken string
	expiresAt   time.Time // absolute expiry
	refreshAt   time.Time // 80% of lifetime threshold
	refreshing  atomic.Bool
	closed      atomic.Bool
}

// NewOAuthTokenCache creates a new OAuth token cache implementing TokenProvider.
// Panics if log is nil (fail-fast constructor pattern). Returns error for invalid config.
func NewOAuthTokenCache(cfg OAuthTokenCacheConfig, log *slog.Logger) (*OAuthTokenCache, error) {
	if log == nil {
		panic("audit: logger is required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if strings.HasPrefix(cfg.TokenURL, "http://") {
		log.Warn("oauth token cache: token URL uses plaintext HTTP — Bearer token will be transmitted without TLS",
			"token_url", cfg.TokenURL)
	}

	baseClient := &http.Client{
		Timeout: cfg.HTTPTimeout,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 2,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	client := opentelemetry.NewInstrumentedHTTPClient(baseClient)

	return &OAuthTokenCache{
		client:       client,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		tokenURL:     cfg.TokenURL,
		scope:        cfg.Scope,
		httpTimeout:  cfg.HTTPTimeout,
		log:          log,
	}, nil
}

// Token returns a valid Bearer token for authenticating to the audit service.
// Safe for concurrent use. Uses cached token when valid, proactive refresh at 80% lifetime,
// and synchronous fetch with double-checked locking when expired.
func (c *OAuthTokenCache) Token(ctx context.Context) (string, error) {
	if c.closed.Load() {
		return "", fmt.Errorf("oauth token cache: closed")
	}

	// Fast path: read lock — check cached token
	c.mu.RLock()
	token := c.accessToken
	now := time.Now()
	hasToken := token != ""
	expired := !now.Before(c.expiresAt)
	needsRefresh := hasToken && !expired && !now.Before(c.refreshAt)
	c.mu.RUnlock()

	// Valid token, not yet at refresh threshold → return immediately
	if hasToken && !expired && !needsRefresh {
		return token, nil
	}

	// Valid token but past refresh threshold → trigger async refresh, return cached
	if hasToken && !expired && needsRefresh {
		c.triggerAsyncRefresh()
		return token, nil
	}

	// Expired or no token → synchronous fetch with double-checked locking
	c.mu.Lock()
	// Re-check: another goroutine may have fetched while we waited for write lock
	if c.accessToken != "" && time.Now().Before(c.expiresAt) {
		token = c.accessToken
		c.mu.Unlock()
		return token, nil
	}
	// Still expired/missing → fetch under write lock
	token, err := c.fetchToken(ctx)
	c.mu.Unlock()
	return token, err
}

// fetchToken performs the OAuth client_credentials grant request and stores the result.
// MUST be called with c.mu write lock held. Used for the synchronous (expired token) path
// where double-checked locking requires the lock to be held throughout.
func (c *OAuthTokenCache) fetchToken(ctx context.Context) (string, error) {
	tokenResp, err := c.doTokenRequest(ctx)
	if err != nil {
		return "", err
	}
	c.storeTokenData(tokenResp)
	return tokenResp.AccessToken, nil
}

// doTokenRequest performs the HTTP POST to the token endpoint and validates the response.
// Lock-free — does NOT touch cache fields. Safe to call without holding any lock.
func (c *OAuthTokenCache) doTokenRequest(ctx context.Context) (*oauthTokenResponse, error) {
	// Build form-encoded body (G19: url.Values for proper encoding)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if c.scope != "" {
		form.Set("scope", c.scope)
	}
	body := form.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("oauth token cache: request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Basic Auth: base64(client_id:client_secret) per RFC 6749 Section 2.3.1
	credentials := base64.StdEncoding.EncodeToString([]byte(c.clientID + ":" + c.clientSecret))
	req.Header.Set("Authorization", "Basic "+credentials)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth token cache: network error: %w", err)
	}
	defer resp.Body.Close()

	// Bounded read (G18: io.LimitReader)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth token cache: error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// G10: do NOT echo response body — include only status code
		return nil, fmt.Errorf("oauth token cache: token request failed with status %d", resp.StatusCode)
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("oauth token cache: invalid token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("oauth token cache: empty access_token in response")
	}

	// G20: validate token_type is "Bearer" (case-insensitive per OAuth 2.1)
	if !strings.EqualFold(tokenResp.TokenType, "Bearer") {
		return nil, fmt.Errorf("oauth token cache: unsupported token_type %q, expected Bearer", tokenResp.TokenType)
	}

	// G16: validate expires_in > 0
	if tokenResp.ExpiresIn <= 0 {
		return nil, fmt.Errorf("oauth token cache: invalid expires_in %d, must be positive", tokenResp.ExpiresIn)
	}

	// Defense-in-depth: warn about unusually long token lifetimes (> 24h)
	if tokenResp.ExpiresIn > 86400 {
		c.log.Warn("oauth token cache: token lifetime exceeds 24 hours — verify auth server configuration",
			"expires_in", tokenResp.ExpiresIn)
	}

	return &tokenResp, nil
}

// storeTokenData stores a validated token response into the cache fields.
// MUST be called with c.mu write lock held.
func (c *OAuthTokenCache) storeTokenData(tokenResp *oauthTokenResponse) {
	now := time.Now()
	lifetime := time.Duration(tokenResp.ExpiresIn) * time.Second
	c.accessToken = tokenResp.AccessToken
	c.expiresAt = now.Add(lifetime)
	c.refreshAt = now.Add(time.Duration(float64(lifetime) * 0.8))

	// G11: NEVER log token value
	c.log.Info("oauth token cache: token obtained",
		"expires_in", tokenResp.ExpiresIn,
		"scope", tokenResp.Scope)
}

// triggerAsyncRefresh starts a background goroutine to refresh the token.
// Uses atomic.Bool CAS as single-flight guard — only one refresh at a time.
// The HTTP call is made WITHOUT holding the lock — only the storage step acquires
// the write lock. This ensures Token() callers are never blocked by async refresh.
func (c *OAuthTokenCache) triggerAsyncRefresh() {
	// Single-flight: only one goroutine refreshes at a time
	if !c.refreshing.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer c.refreshing.Store(false)

		ctx, cancel := context.WithTimeout(context.Background(), c.httpTimeout)
		defer cancel()

		// HTTP call WITHOUT holding the lock (non-blocking for Token() callers)
		tokenResp, err := c.doTokenRequest(ctx)
		if err != nil {
			// G11: log error without token or client_secret
			c.log.Warn("oauth token cache: proactive refresh failed", "error", err)
			return
		}

		// Check closed before storing — avoid writing to a shut-down cache
		if c.closed.Load() {
			return
		}

		// Store under write lock (brief — no I/O)
		c.mu.Lock()
		c.storeTokenData(tokenResp)
		c.mu.Unlock()

		c.log.Info("oauth token cache: proactive refresh succeeded")
	}()
}

// Close stops the token cache. Subsequent Token() calls return an error.
// Clears the cached token to allow earlier GC collection.
func (c *OAuthTokenCache) Close() error {
	c.closed.Store(true)
	c.mu.Lock()
	c.accessToken = ""
	c.mu.Unlock()
	c.client.CloseIdleConnections()
	c.log.Info("oauth token cache: closed")
	return nil
}

var _ TokenProvider = (*OAuthTokenCache)(nil)
var _ io.Closer = (*OAuthTokenCache)(nil)
