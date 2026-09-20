package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is the multi-replica Store of DESIGN §5: taint and tool pins survive a
// restart and are shared between inspector replicas, which the in-memory store
// cannot do.
//
// Keys are namespaced and TTL-bounded. Nothing here stores content — a taint
// key holds no value at all, and a pin holds a hash.
type Redis struct {
	client redis.UniversalClient
	prefix string
}

// NewRedis wraps a client. The prefix namespaces every key; pass "" for the
// default.
func NewRedis(client redis.UniversalClient, prefix string) *Redis {
	if prefix == "" {
		prefix = "ai_security"
	}
	return &Redis{client: client, prefix: prefix}
}

var _ Store = (*Redis)(nil)

func (r *Redis) taintKey(session string) string {
	return fmt.Sprintf("%s:taint:{%s}", r.prefix, session)
}

func (r *Redis) pinKey(session, tool string) string {
	return fmt.Sprintf("%s:pin:{%s}:%s", r.prefix, session, tool)
}

func (r *Redis) Tainted(ctx context.Context, session string) (bool, error) {
	n, err := r.client.Exists(ctx, r.taintKey(session)).Result()
	if err != nil {
		return false, fmt.Errorf("session: tainted: %w", err)
	}
	return n > 0, nil
}

func (r *Redis) Taint(ctx context.Context, session string, ttl time.Duration) error {
	if ttl < 0 {
		ttl = 0 // go-redis treats 0 as no expiry, like the in-memory store
	}
	if err := r.client.Set(ctx, r.taintKey(session), "1", ttl).Err(); err != nil {
		return fmt.Errorf("session: taint: %w", err)
	}
	return nil
}

func (r *Redis) ToolPin(ctx context.Context, session, tool string) (string, bool, error) {
	hash, err := r.client.Get(ctx, r.pinKey(session, tool)).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("session: tool pin: %w", err)
	}
	return hash, true, nil
}

func (r *Redis) PinTool(ctx context.Context, session, tool, hash string, ttl time.Duration) error {
	if ttl < 0 {
		ttl = 0
	}
	if err := r.client.Set(ctx, r.pinKey(session, tool), hash, ttl).Err(); err != nil {
		return fmt.Errorf("session: pin tool: %w", err)
	}
	return nil
}
