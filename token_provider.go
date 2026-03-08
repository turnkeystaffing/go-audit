package audit

import "context"

// TokenProvider is the abstraction boundary between HTTPWriter and token management.
// Implementations range from static tokens (testing) to full OAuth client_credentials
// caches (production). Story 2-2 implements the OAuth token cache behind this interface.
type TokenProvider interface {
	// Token returns a valid Bearer token for authenticating to the audit service.
	// Implementations must be safe for concurrent use.
	Token(ctx context.Context) (string, error)
}

// StaticTokenProvider returns a fixed token string on every call.
// Useful for testing and scenarios where tokens are managed externally.
type StaticTokenProvider struct {
	token string
}

// NewStaticTokenProvider creates a TokenProvider that always returns the given token.
func NewStaticTokenProvider(token string) *StaticTokenProvider {
	return &StaticTokenProvider{token: token}
}

// Token returns the static token.
func (p *StaticTokenProvider) Token(_ context.Context) (string, error) {
	return p.token, nil
}

var _ TokenProvider = (*StaticTokenProvider)(nil)
