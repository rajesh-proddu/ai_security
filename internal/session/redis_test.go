package session

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is exercised against a real server, because the interesting parts —
// TTL expiry, a missing key versus an empty value — are Redis semantics, not
// ours, and a fake would only assert that the fake behaves like the fake.
//
// Set REDIS_ADDR to run it:
//
//	docker run --rm -d -p 6379:6379 redis:7-alpine
//	REDIS_ADDR=localhost:6379 go test ./internal/session/
func testRedis(t *testing.T) *Redis {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("REDIS_ADDR is not set")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// Namespace per test so runs cannot collide.
	return NewRedis(client, "ai_security_test:"+t.Name())
}

func TestRedisTaint(t *testing.T) {
	r := testRedis(t)
	ctx := context.Background()

	tainted, err := r.Tainted(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if tainted {
		t.Fatal("an unknown session must not be tainted")
	}

	if err := r.Taint(ctx, "s1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if tainted, err = r.Tainted(ctx, "s1"); err != nil || !tainted {
		t.Fatalf("tainted = %v, err = %v", tainted, err)
	}
	if other, _ := r.Tainted(ctx, "s2"); other {
		t.Error("taint must not leak between sessions")
	}
}

func TestRedisTaintExpires(t *testing.T) {
	r := testRedis(t)
	ctx := context.Background()
	if err := r.Taint(ctx, "s1", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	tainted, err := r.Tainted(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if tainted {
		t.Fatal("taint must expire with its TTL")
	}
}

func TestRedisToolPins(t *testing.T) {
	r := testRedis(t)
	ctx := context.Background()

	if _, ok, err := r.ToolPin(ctx, "s1", "email.send"); err != nil || ok {
		t.Fatalf("unpinned tool: ok = %v, err = %v", ok, err)
	}
	if err := r.PinTool(ctx, "s1", "email.send", "sha256:abc", time.Minute); err != nil {
		t.Fatal(err)
	}

	hash, ok, err := r.ToolPin(ctx, "s1", "email.send")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || hash != "sha256:abc" {
		t.Fatalf("pin = %q, ok = %v", hash, ok)
	}
	if _, ok, _ := r.ToolPin(ctx, "s2", "email.send"); ok {
		t.Error("a pin must not leak across sessions")
	}
	if _, ok, _ := r.ToolPin(ctx, "s1", "email.read"); ok {
		t.Error("a pin must not leak across tools")
	}
}

// The two stores must be interchangeable: the pipeline only knows Store.
func TestRedisMatchesMemorySemantics(t *testing.T) {
	r := testRedis(t)
	stores := map[string]Store{"memory": NewMemory(), "redis": r}
	ctx := context.Background()

	for name, s := range stores {
		t.Run(name, func(t *testing.T) {
			if tainted, err := s.Tainted(ctx, "fresh"); err != nil || tainted {
				t.Errorf("fresh session: tainted = %v, err = %v", tainted, err)
			}
			if err := s.Taint(ctx, "fresh", time.Minute); err != nil {
				t.Fatal(err)
			}
			if tainted, _ := s.Tainted(ctx, "fresh"); !tainted {
				t.Error("taint did not stick")
			}
			if _, ok, _ := s.ToolPin(ctx, "fresh", "t"); ok {
				t.Error("unset pin reported as present")
			}
			if err := s.PinTool(ctx, "fresh", "t", "h", time.Minute); err != nil {
				t.Fatal(err)
			}
			if h, ok, _ := s.ToolPin(ctx, "fresh", "t"); !ok || h != "h" {
				t.Errorf("pin = %q, ok = %v", h, ok)
			}
		})
	}
}
