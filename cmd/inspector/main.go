// Command inspector is the ai_security inspection service data plane.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	"github.com/rajesh-proddu/ai_security/internal/adapters/agentgateway"
	httpadapter "github.com/rajesh-proddu/ai_security/internal/adapters/http"
	"github.com/rajesh-proddu/ai_security/internal/audit"
	"github.com/rajesh-proddu/ai_security/internal/core"
	"github.com/rajesh-proddu/ai_security/internal/detect"
	"github.com/rajesh-proddu/ai_security/internal/normalize"
	"github.com/rajesh-proddu/ai_security/internal/policy"
	"github.com/rajesh-proddu/ai_security/internal/session"
)

type config struct {
	addr        string
	grpcAddr    string
	redisAddr   string
	policyFile  string
	auditFile   string
	taintTTL    time.Duration
	shutdownTTL time.Duration
}

func loadConfig() (config, error) {
	c := config{
		addr:        env("ADDR", ":8080"),
		grpcAddr:    env("GRPC_ADDR", ":9000"),
		redisAddr:   os.Getenv("REDIS_ADDR"),
		policyFile:  os.Getenv("POLICY_FILE"),
		auditFile:   os.Getenv("AUDIT_FILE"),
		taintTTL:    time.Hour,
		shutdownTTL: 10 * time.Second,
	}
	if v := os.Getenv("TAINT_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return config{}, err
		}
		c.taintTTL = d
	}
	return c, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("inspector: %v", err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	pol := policy.Default()
	if cfg.policyFile != "" {
		pol, err = policy.LoadFile(cfg.policyFile)
		if err != nil {
			return err
		}
	}

	auditOut := os.Stdout
	if cfg.auditFile != "" {
		f, err := os.OpenFile(cfg.auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		auditOut = f
	}

	// The fast set of DESIGN §3.3. The tenant dictionary and the URL allow-list
	// have nowhere to be configured yet (see detect.CustomDict), so they are
	// empty here and match nothing.
	registry, err := detect.V1(nil, nil)
	if err != nil {
		return err
	}

	// Taint and tool pins are shared state: with more than one replica they
	// belong in Redis (DESIGN §5), and in memory only for a single process.
	var sessions session.Store = session.NewMemory()
	if cfg.redisAddr != "" {
		client := redis.NewClient(&redis.Options{Addr: cfg.redisAddr})
		defer client.Close()
		pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := client.Ping(pingCtx).Err()
		cancel()
		if err != nil {
			return fmt.Errorf("redis at %s: %w", cfg.redisAddr, err)
		}
		sessions = session.NewRedis(client, "")
	}

	pipeline := core.NewPipeline(
		registry,
		policy.NewEvaluator(pol),
		sessions,
		audit.NewJSONLSink(auditOut),
		cfg.taintTTL,
	)
	pipeline.Normalizer = normalize.Normalizer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	httpadapter.NewHandler(pipeline).Register(mux)

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// agentgateway's two hooks, ext_proc (LLM routes) and ExtMcp (MCP routes),
	// share one gRPC listener (DESIGN §3.2; port contract in ai_platform
	// gateway/README.md).
	grpcSrv := grpc.NewServer(agentgateway.ServerOptions()...)
	agentgateway.Register(grpcSrv, pipeline)
	lis, err := net.Listen("tcp", cfg.grpcAddr)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 2)
	go func() {
		log.Printf("inspector listening on %s (tenant=%q policy_version=%s)", cfg.addr, pol.Tenant, pol.Version)
		errc <- srv.ListenAndServe()
	}()
	go func() {
		log.Printf("inspector gRPC (ext_proc, ExtMcp) listening on %s", cfg.grpcAddr)
		errc <- grpcSrv.Serve(lis)
	}()

	select {
	case err := <-errc:
		grpcSrv.Stop()
		_ = srv.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Print("inspector shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTTL)
		defer cancel()
		stopped := make(chan struct{})
		go func() { grpcSrv.GracefulStop(); close(stopped) }()
		err := srv.Shutdown(shutdownCtx)
		select {
		case <-stopped:
		case <-shutdownCtx.Done():
			grpcSrv.Stop()
		}
		return err
	}
}
