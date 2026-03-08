//go:build integration

package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	redismodule "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

// redisTestInfra provides a shared Redis container for integration tests.
type redisTestInfra struct {
	Container testcontainers.Container
	Host      string
	Port      int
	Addr      string
}

func setupRedisInfra() (_ *redisTestInfra, retErr error) {
	ctx := context.Background()
	infra := &redisTestInfra{}

	defer func() {
		if retErr != nil {
			infra.cleanupNoT()
		}
	}()

	redisContainer, err := redismodule.RunContainer(ctx,
		testcontainers.WithImage("redis:7-alpine"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start redis container: %w", err)
	}
	infra.Container = redisContainer

	host, err := redisContainer.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get redis host: %w", err)
	}
	port, err := mappedPortWithRetry(ctx, redisContainer, "6379")
	if err != nil {
		return nil, err
	}
	infra.Host = host
	infra.Port = port.Int()
	infra.Addr = fmt.Sprintf("%s:%d", host, port.Int())

	return infra, nil
}

func (infra *redisTestInfra) cleanupNoT() {
	if infra.Container != nil {
		if err := infra.Container.Terminate(context.Background()); err != nil {
			fmt.Printf("Failed to terminate Redis container: %v\n", err)
		}
	}
}

func mappedPortWithRetry(ctx context.Context, container testcontainers.Container, port string) (nat.Port, error) {
	const retryAttempts = 5
	const retryDelay = 300 * time.Millisecond

	natPort := nat.Port(port + "/tcp")
	for i := 0; i < retryAttempts; i++ {
		mappedPort, err := container.MappedPort(ctx, natPort)
		if err == nil {
			return mappedPort, nil
		}
		time.Sleep(retryDelay)
	}
	return "", fmt.Errorf("failed to get mapped port %s after %d attempts", port, retryAttempts)
}
