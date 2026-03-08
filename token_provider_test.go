package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticTokenProvider_Token(t *testing.T) {
	token := "test-token-" + t.Name()
	provider := NewStaticTokenProvider(token)

	got, err := provider.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, token, got)
}

func TestStaticTokenProvider_Token_EmptyString(t *testing.T) {
	provider := NewStaticTokenProvider("")

	got, err := provider.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "", got)
}

func TestStaticTokenProvider_ImplementsInterface(t *testing.T) {
	var _ TokenProvider = (*StaticTokenProvider)(nil)
}
