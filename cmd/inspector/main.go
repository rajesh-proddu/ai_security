// Command inspector is the ai_security inspection service data plane.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	httpadapter "github.com/rajesh-proddu/ai_security/internal/adapters/http"
	"github.com/rajesh-proddu/ai_security/internal/audit"
	"github.com/rajesh-proddu/ai_security/internal/core"
	"github.com/rajesh-proddu/ai_security/internal/detect"
	"github.com/rajesh-proddu/ai_security/internal/policy"
	"github.com/rajesh-proddu/ai_security/internal/session"
)

type config struct {
	addr        string
	policyFile  string
	auditFile   string
	taintTTL    time.Duration
	shutdownTTL time.Duration
}

func loadConfig() (config, error) {
	c := config{
		addr:        env("ADDR", ":8080"),
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

	// Phase 0 runs the no-op detector: the v1 set of DESIGN §3.3 lands in Phase 1.
	registry, err := detect.NewRegistry(detect.Noop{})
	if err != nil {
		return err
	}

	pipeline := core.NewPipeline(
		registry,
		policy.NewEvaluator(pol),
		session.NewMemory(),
		audit.NewJSONLSink(auditOut),
		cfg.taintTTL,
	)

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Printf("inspector listening on %s (tenant=%q policy_version=%s)", cfg.addr, pol.Tenant, pol.Version)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Print("inspector shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTTL)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
