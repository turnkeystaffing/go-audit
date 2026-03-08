//go:build integration

package audit

import (
	"fmt"
	"os"
	"testing"
)

var sharedRedisAddr string

func TestMain(m *testing.M) {
	redisInfra, err := setupRedisInfra()
	if err != nil {
		fmt.Printf("pkg/audit integration test infra setup failed: %v\n", err)
		os.Exit(1)
	}

	sharedRedisAddr = redisInfra.Addr

	code := m.Run()

	redisInfra.cleanupNoT()
	os.Exit(code)
}
