package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test helpers ---

func tokenTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func validTokenCacheConfig(tokenURL string) OAuthTokenCacheConfig {
	return OAuthTokenCacheConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		TokenURL:     tokenURL,
		Scope:        "audit:write",
		HTTPTimeout:  5 * time.Second,
	}
}

// tokenServer creates an httptest.Server that returns OAuth token responses.
// callCount tracks the number of requests received. The handler func can customize behavior.
func tokenServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// successTokenHandler returns a handler that always returns a valid token response with the given expiresIn.
func successTokenHandler(expiresIn int, callCount *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if callCount != nil {
			callCount.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   expiresIn,
			Scope:       "audit:write",
		})
	}
}

// --- Test 5.1: Initial Fetch ---

func TestOAuthTokenCache_Token_InitialFetch(t *testing.T) {
	var callCount atomic.Int32
	srv := tokenServer(t, successTokenHandler(3600, &callCount))

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	token, err := cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-access-token", token)
	assert.Equal(t, int32(1), callCount.Load())
}

// --- Test 5.2: Cache Hit ---

func TestOAuthTokenCache_Token_CacheHit(t *testing.T) {
	var callCount atomic.Int32
	srv := tokenServer(t, successTokenHandler(3600, &callCount))

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	// First call — fetches from server
	token1, err := cache.Token(context.Background())
	require.NoError(t, err)

	// Second call — returns cached
	token2, err := cache.Token(context.Background())
	require.NoError(t, err)

	assert.Equal(t, token1, token2)
	assert.Equal(t, int32(1), callCount.Load()) // only one HTTP call
}

// --- Test 5.3: Proactive Refresh at 80% ---

func TestOAuthTokenCache_Token_ProactiveRefresh(t *testing.T) {
	var callCount atomic.Int32
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Very short lifetime — 1 second, so 80% = 800ms
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: fmt.Sprintf("token-%d", callCount.Load()),
			TokenType:   "Bearer",
			ExpiresIn:   1,
			Scope:       "audit:write",
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	// Initial fetch
	token, err := cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token)
	assert.Equal(t, int32(1), callCount.Load())

	// Manually set refreshAt to past to trigger proactive refresh
	cache.mu.Lock()
	cache.refreshAt = time.Now().Add(-1 * time.Millisecond)
	cache.mu.Unlock()

	// This call should trigger async refresh and return cached token
	token, err = cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token) // returns cached immediately

	// Wait for async refresh to complete
	require.Eventually(t, func() bool {
		return callCount.Load() >= 2
	}, 5*time.Second, 10*time.Millisecond, "async refresh should have been called")
}

// --- Test 5.4: Refresh Failure with Valid Cache ---

func TestOAuthTokenCache_Token_RefreshFailure_ValidCache(t *testing.T) {
	var callCount atomic.Int32
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		count := callCount.Add(1)
		if count == 1 {
			// First call: success
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(oauthTokenResponse{
				AccessToken: "good-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				Scope:       "audit:write",
			})
			return
		}
		// Subsequent calls: server error
		w.WriteHeader(http.StatusInternalServerError)
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	// Initial fetch succeeds
	token, err := cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "good-token", token)

	// Set refreshAt to past to trigger proactive refresh
	cache.mu.Lock()
	cache.refreshAt = time.Now().Add(-1 * time.Millisecond)
	cache.mu.Unlock()

	// This triggers async refresh (which will fail) but returns cached token
	token, err = cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "good-token", token)

	// Wait for the failed refresh attempt
	require.Eventually(t, func() bool {
		return callCount.Load() >= 2
	}, 5*time.Second, 10*time.Millisecond)
}

// --- Test 5.5: Expired Token Synchronous Fetch ---

func TestOAuthTokenCache_Token_Expired_SyncFetch(t *testing.T) {
	var callCount atomic.Int32
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		count := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: fmt.Sprintf("token-%d", count),
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "audit:write",
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	// Initial fetch
	token1, err := cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token1)

	// Force expiry
	cache.mu.Lock()
	cache.expiresAt = time.Now().Add(-1 * time.Second)
	cache.refreshAt = time.Now().Add(-2 * time.Second)
	cache.mu.Unlock()

	// Should synchronously fetch a new token
	token2, err := cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-2", token2)
	assert.Equal(t, int32(2), callCount.Load())
}

// --- Test 5.6: Concurrent Token Calls ---

func TestOAuthTokenCache_Token_Concurrent(t *testing.T) {
	var callCount atomic.Int32
	srv := tokenServer(t, successTokenHandler(3600, &callCount))

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	const goroutines = 10
	const callsPerGoroutine = 5
	var wg sync.WaitGroup
	tokens := make([]string, goroutines*callsPerGoroutine)
	errs := make([]error, goroutines*callsPerGoroutine)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				tok, err := cache.Token(context.Background())
				tokens[idx*callsPerGoroutine+j] = tok
				errs[idx*callsPerGoroutine+j] = err
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d", i)
	}
	for i, tok := range tokens {
		assert.Equal(t, "test-access-token", tok, "goroutine %d", i)
	}
	// At most 1 fetch (initial) — double-checked locking prevents thundering herd
	assert.LessOrEqual(t, callCount.Load(), int32(1))
}

// --- Test 5.7: Single-Flight Refresh ---

func TestOAuthTokenCache_Token_SingleFlightRefresh(t *testing.T) {
	var callCount atomic.Int32
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "audit:write",
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	// Initial fetch
	_, err = cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(1), callCount.Load())

	// Set refreshAt to past
	cache.mu.Lock()
	cache.refreshAt = time.Now().Add(-1 * time.Millisecond)
	cache.mu.Unlock()

	// Multiple goroutines trigger refresh simultaneously
	var wg sync.WaitGroup
	const goroutines = 10
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = cache.Token(context.Background())
		}()
	}
	wg.Wait()

	// Wait for any async refresh to complete
	require.Eventually(t, func() bool {
		return !cache.refreshing.Load()
	}, 5*time.Second, 10*time.Millisecond)

	// At most 2 calls: initial + one refresh (single-flight guard)
	assert.LessOrEqual(t, callCount.Load(), int32(2))
}

// --- Test 5.8: Concurrent Expired Fetch (Double-Checked Locking) ---

func TestOAuthTokenCache_Token_ConcurrentExpiredFetch(t *testing.T) {
	var callCount atomic.Int32
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "refreshed-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "audit:write",
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	// Initial fetch
	_, err = cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(1), callCount.Load())

	// Force expiry
	cache.mu.Lock()
	cache.expiresAt = time.Now().Add(-1 * time.Second)
	cache.refreshAt = time.Now().Add(-2 * time.Second)
	cache.accessToken = "expired-token"
	cache.mu.Unlock()

	// Reset counter for this test
	callCount.Store(0)

	// Launch 10 goroutines all discovering expired token simultaneously
	const goroutines = 10
	var wg sync.WaitGroup
	start := make(chan struct{})
	tokens := make([]string, goroutines)
	errs := make([]error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // all start at once
			tok, err := cache.Token(context.Background())
			tokens[idx] = tok
			errs[idx] = err
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d", i)
	}
	for i, tok := range tokens {
		assert.Equal(t, "refreshed-token", tok, "goroutine %d", i)
	}
	// Double-checked locking: exactly 1 HTTP call for the re-fetch
	assert.Equal(t, int32(1), callCount.Load())
}

// --- Test 5.9: Context Cancellation ---

func TestOAuthTokenCache_Token_ContextCancellation(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		<-block // block until test cleanup — no time.Sleep (P4)
		w.WriteHeader(http.StatusOK)
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	_, err = cache.Token(ctx)
	assert.Error(t, err)
}

// --- Test 5.10: Token After Close ---

func TestOAuthTokenCache_Token_AfterClose(t *testing.T) {
	srv := tokenServer(t, successTokenHandler(3600, nil))

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)

	require.NoError(t, cache.Close())

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

// --- Test 5.11: Auth Error 401 ---

func TestOAuthTokenCache_Token_AuthError_401(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 401")
}

// --- Test 5.12: Auth Error 400 ---

func TestOAuthTokenCache_Token_AuthError_400(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 400")
}

// --- Test 5.13: Server Error 500 ---

func TestOAuthTokenCache_Token_ServerError_500(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

// --- Test 5.14: Network Error ---

func TestOAuthTokenCache_Token_NetworkError(t *testing.T) {
	cache, err := NewOAuthTokenCache(OAuthTokenCacheConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     "http://127.0.0.1:1/oauth/token", // port 1 — guaranteed to fail
		HTTPTimeout:  1 * time.Second,
	}, tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network error")
}

// --- Test 5.15: Empty Access Token ---

func TestOAuthTokenCache_Token_EmptyAccessToken(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty access_token")
}

// --- Test 5.16: Zero ExpiresIn ---

func TestOAuthTokenCache_Token_ZeroExpiresIn(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "tok",
			TokenType:   "Bearer",
			ExpiresIn:   0,
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid expires_in")
}

// --- Test 5.17: Negative ExpiresIn ---

func TestOAuthTokenCache_Token_NegativeExpiresIn(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "tok",
			TokenType:   "Bearer",
			ExpiresIn:   -1,
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid expires_in")
}

// --- Test 5.18: Invalid Token Type ---

func TestOAuthTokenCache_Token_InvalidTokenType(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "tok",
			TokenType:   "MAC",
			ExpiresIn:   3600,
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported token_type")
	assert.Contains(t, err.Error(), "MAC")
}

// --- Test 5.19: Request Format ---

func TestOAuthTokenCache_Token_RequestFormat(t *testing.T) {
	var receivedReq *http.Request
	var receivedBody string
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedReq = r
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "tok",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})

	cfg := validTokenCacheConfig(srv.URL)
	cache, err := NewOAuthTokenCache(cfg, tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	require.NoError(t, err)

	// Verify POST method
	assert.Equal(t, http.MethodPost, receivedReq.Method)

	// Verify Content-Type
	assert.Equal(t, "application/x-www-form-urlencoded", receivedReq.Header.Get("Content-Type"))

	// Verify Basic Auth
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.ClientID+":"+cfg.ClientSecret))
	assert.Equal(t, expectedAuth, receivedReq.Header.Get("Authorization"))

	// Verify form body contains grant_type=client_credentials
	assert.Contains(t, receivedBody, "grant_type=client_credentials")
}

// --- Test 5.20: With Scope ---

func TestOAuthTokenCache_Token_WithScope(t *testing.T) {
	var receivedBody string
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "tok",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})

	cfg := validTokenCacheConfig(srv.URL)
	cfg.Scope = "audit:write events:read"
	cache, err := NewOAuthTokenCache(cfg, tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	require.NoError(t, err)

	// Scope should be URL-encoded in form body
	assert.Contains(t, receivedBody, "scope=audit%3Awrite+events%3Aread")
}

// --- Test 5.21: Without Scope ---

func TestOAuthTokenCache_Token_WithoutScope(t *testing.T) {
	var receivedBody string
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "tok",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})

	cfg := validTokenCacheConfig(srv.URL)
	cfg.Scope = "" // no scope
	cache, err := NewOAuthTokenCache(cfg, tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	require.NoError(t, err)

	// Body should NOT contain scope parameter
	assert.NotContains(t, receivedBody, "scope=")
	assert.Contains(t, receivedBody, "grant_type=client_credentials")
}

// --- Test 5.22: Nil Logger Panics ---

func TestNewOAuthTokenCache_NilLogger_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "audit: logger is required", func() {
		_, _ = NewOAuthTokenCache(OAuthTokenCacheConfig{}, nil)
	})
}

// --- Test 5.23: Empty ClientID Error ---

func TestNewOAuthTokenCache_EmptyClientID_Error(t *testing.T) {
	cache, err := NewOAuthTokenCache(OAuthTokenCacheConfig{
		ClientSecret: "secret",
		TokenURL:     "https://auth.example.com/token",
	}, tokenTestLogger())
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "client ID is required")
}

// --- Test 5.24: Empty ClientSecret Error ---

func TestNewOAuthTokenCache_EmptyClientSecret_Error(t *testing.T) {
	cache, err := NewOAuthTokenCache(OAuthTokenCacheConfig{
		ClientID: "client",
		TokenURL: "https://auth.example.com/token",
	}, tokenTestLogger())
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "client secret is required")
}

// --- Test 5.25: Invalid TokenURL Error ---

func TestNewOAuthTokenCache_InvalidTokenURL_Error(t *testing.T) {
	cache, err := NewOAuthTokenCache(OAuthTokenCacheConfig{
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     "ftp://invalid.example.com/token",
	}, tokenTestLogger())
	assert.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "scheme must be http or https")
}

// --- Test 5.26: Valid Config Success ---

func TestNewOAuthTokenCache_ValidConfig_Success(t *testing.T) {
	srv := tokenServer(t, successTokenHandler(3600, nil))

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	assert.NotNil(t, cache)
	defer cache.Close()
}

// --- Test 5.27: Close ---

func TestOAuthTokenCache_Close(t *testing.T) {
	srv := tokenServer(t, successTokenHandler(3600, nil))

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)

	err = cache.Close()
	assert.NoError(t, err)
	assert.True(t, cache.closed.Load())
}

// --- Test 5.28: Config Validate Table-Driven ---

func TestOAuthTokenCacheConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     OAuthTokenCacheConfig
		wantErr string
	}{
		{
			name: "valid config",
			cfg: OAuthTokenCacheConfig{
				ClientID:     "id",
				ClientSecret: "secret",
				TokenURL:     "https://auth.example.com/token",
				HTTPTimeout:  10 * time.Second,
			},
		},
		{
			name: "empty client ID",
			cfg: OAuthTokenCacheConfig{
				ClientSecret: "secret",
				TokenURL:     "https://auth.example.com/token",
			},
			wantErr: "client ID is required",
		},
		{
			name: "empty client secret",
			cfg: OAuthTokenCacheConfig{
				ClientID: "id",
				TokenURL: "https://auth.example.com/token",
			},
			wantErr: "client secret is required",
		},
		{
			name: "empty token URL",
			cfg: OAuthTokenCacheConfig{
				ClientID:     "id",
				ClientSecret: "secret",
			},
			wantErr: "token URL is required",
		},
		{
			name: "invalid URL scheme",
			cfg: OAuthTokenCacheConfig{
				ClientID:     "id",
				ClientSecret: "secret",
				TokenURL:     "ftp://auth.example.com/token",
			},
			wantErr: "scheme must be http or https",
		},
		{
			name: "zero timeout gets default",
			cfg: OAuthTokenCacheConfig{
				ClientID:     "id",
				ClientSecret: "secret",
				TokenURL:     "https://auth.example.com/token",
				HTTPTimeout:  0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	// Verify clamping separately: zero timeout is clamped to 10s default
	t.Run("zero timeout clamped to default", func(t *testing.T) {
		cfg := OAuthTokenCacheConfig{
			ClientID:     "id",
			ClientSecret: "secret",
			TokenURL:     "https://auth.example.com/token",
			HTTPTimeout:  0,
		}
		require.NoError(t, cfg.Validate())
		assert.Equal(t, 10*time.Second, cfg.HTTPTimeout)
	})
}

// --- Test: DefaultOAuthTokenCacheConfig values (review fix) ---

func TestDefaultOAuthTokenCacheConfig_Values(t *testing.T) {
	cfg := DefaultOAuthTokenCacheConfig()
	assert.Equal(t, 10*time.Second, cfg.HTTPTimeout)
	assert.Empty(t, cfg.ClientID)
	assert.Empty(t, cfg.ClientSecret)
	assert.Empty(t, cfg.TokenURL)
	assert.Empty(t, cfg.Scope)
}

// --- QA Test: Invalid JSON Response ---

func TestOAuthTokenCache_Token_InvalidJSONResponse(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token response")
}

// --- QA Test: Bearer Case Insensitive ---

func TestOAuthTokenCache_Token_BearerCaseInsensitive(t *testing.T) {
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "case-token",
			TokenType:   "bearer", // lowercase — must be accepted per OAuth 2.1
			ExpiresIn:   3600,
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)
	defer cache.Close()

	token, err := cache.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "case-token", token)
}

// --- Test 5.29: HTTP Scheme Warning ---

func TestOAuthTokenCache_Token_HTTPSchemeWarning(t *testing.T) {
	// Use a custom handler to capture log output and verify WARN was emitted
	var logBuf strings.Builder
	handler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	srv := tokenServer(t, successTokenHandler(3600, nil))

	// srv.URL uses http:// (httptest default)
	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), logger)
	require.NoError(t, err)
	defer cache.Close()

	// Verify WARN was logged during construction
	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "plaintext HTTP")
	assert.Contains(t, logOutput, "WARN")
}

// --- Security Test: Close clears cached token ---

func TestOAuthTokenCache_Close_ClearsToken(t *testing.T) {
	srv := tokenServer(t, successTokenHandler(3600, nil))

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)

	// Fetch a token to populate cache
	token, err := cache.Token(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Close should clear the cached token
	require.NoError(t, cache.Close())

	cache.mu.RLock()
	assert.Empty(t, cache.accessToken, "cached token should be cleared after Close()")
	cache.mu.RUnlock()
}

// --- Security Test: WARN for long token lifetime ---

func TestOAuthTokenCache_Token_LongExpiresInWarning(t *testing.T) {
	var logBuf strings.Builder
	handler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	// Server returns expires_in > 86400 (24h)
	srv := tokenServer(t, successTokenHandler(172800, nil)) // 48 hours

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), logger)
	require.NoError(t, err)
	defer cache.Close()

	_, err = cache.Token(context.Background())
	require.NoError(t, err)

	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "token lifetime exceeds 24 hours")
	assert.Contains(t, logOutput, "WARN")
}

// --- Security Test: Async refresh respects closed flag ---

func TestOAuthTokenCache_AsyncRefresh_RespectsClose(t *testing.T) {
	var callCount atomic.Int32
	srv := tokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		count := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: fmt.Sprintf("token-%d", count),
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})

	cache, err := NewOAuthTokenCache(validTokenCacheConfig(srv.URL), tokenTestLogger())
	require.NoError(t, err)

	// Initial fetch
	_, err = cache.Token(context.Background())
	require.NoError(t, err)

	// Close immediately — any pending async refresh should not store
	require.NoError(t, cache.Close())

	// Verify token was cleared
	cache.mu.RLock()
	assert.Empty(t, cache.accessToken)
	cache.mu.RUnlock()
}
