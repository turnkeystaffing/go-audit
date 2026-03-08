package audit

import (
	"fmt"
	"log/slog"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

// ProducerRouterConfig configures the NewProducerRouter factory for producer-side audit wiring.
// When RedisClient is provided: three-tier chain HTTPWriter → RedisQueueWriter → FileWriter.
// When RedisClient is nil: two-tier chain HTTPWriter → FileWriter (Redis skipped entirely).
type ProducerRouterConfig struct {
	HTTP          HTTPWriterConfig       // HTTPWriter configuration (BaseURL, ServiceName, etc.)
	TokenProvider TokenProvider          // OAuth token provider for HTTPWriter authentication
	RedisClient   pkgredis.RedisClient   // Redis client for RedisQueueWriter (nil = skip Redis tier)
	RedisQueue    RedisQueueWriterConfig // RedisQueueWriter configuration (optional, defaults applied)
	FileDir       string                 // FileWriter output directory (required)
	FileReplay    FileReplayConfig       // FileReplayer configuration (optional, defaults from FileDir)
	RouterConfig  *AuditConfig           // Pipeline config override (optional, defaults applied)
}

// ProducerRouter holds the components created by NewProducerRouter.
// Callers manage lifecycle independently: Start the router and replayer, Shutdown in reverse order.
type ProducerRouter struct {
	Router   *AuditRouter
	Replayer *FileReplayer
}

// NewProducerRouter creates an AuditRouter configured with DispatchChain strategy.
// When RedisClient is provided: HTTPWriter → RedisQueueWriter → FileWriter (three-tier).
// When RedisClient is nil: HTTPWriter → FileWriter (two-tier, Redis skipped).
// A FileReplayer is wired to the HTTPWriter for automatic recovery replay.
//
// Panics on nil dependencies (fail-fast pattern). Returns error for configuration issues.
func NewProducerRouter(cfg ProducerRouterConfig, log *slog.Logger) (*ProducerRouter, error) {
	if log == nil {
		panic("NewProducerRouter: log cannot be nil")
	}
	if cfg.TokenProvider == nil {
		panic("NewProducerRouter: TokenProvider cannot be nil")
	}
	if cfg.FileDir == "" {
		return nil, fmt.Errorf("producer router: FileDir is required")
	}

	// --- HTTPWriter (tier 1: primary) ---
	httpWriter, err := NewHTTPWriter(cfg.HTTP, cfg.TokenProvider, log)
	if err != nil {
		return nil, fmt.Errorf("producer router: http writer: %w", err)
	}

	// --- FileWriter (last-resort tier) ---
	fileWriter, err := NewFileWriter(cfg.FileDir, "daily", 100*1024*1024, log) // 100MB rotation
	if err != nil {
		return nil, fmt.Errorf("producer router: file writer: %w", err)
	}

	// --- AuditRouter with DispatchChain ---
	routerCfg := cfg.RouterConfig
	if routerCfg == nil {
		routerCfg = DefaultConfig()
	}
	routerCfg.DispatchStrategy = DispatchChain

	redisClient := cfg.RedisClient
	if redisClient == nil {
		redisClient = pkgredis.NewNoopClient()
	}
	router := NewAuditRouter(routerCfg, log, redisClient)

	// Registration order = fallback priority
	router.RegisterWriter(httpWriter, true)

	// --- RedisQueueWriter (tier 2: fallback) — only when Redis is available ---
	if cfg.RedisClient != nil {
		cfg.RedisQueue.Validate()
		redisWriter, redisErr := NewRedisQueueWriter(cfg.RedisQueue, cfg.RedisClient, log)
		if redisErr != nil {
			return nil, fmt.Errorf("producer router: redis queue writer: %w", redisErr)
		}
		router.RegisterWriter(redisWriter, false)
	}

	router.RegisterWriter(fileWriter, false)

	// --- FileReplayer wired to HTTPWriter ---
	replayCfg := cfg.FileReplay
	if replayCfg.Directory == "" {
		replayCfg = DefaultFileReplayConfig(cfg.FileDir)
	}
	replayer, err := NewFileReplayer(replayCfg, httpWriter, log)
	if err != nil {
		return nil, fmt.Errorf("producer router: file replayer: %w", err)
	}

	return &ProducerRouter{
		Router:   router,
		Replayer: replayer,
	}, nil
}
