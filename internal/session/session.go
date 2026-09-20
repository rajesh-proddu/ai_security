// Package session holds the cross-surface state of DESIGN §3.4: whether a
// session has read injected content (taint), and the tool-definition hashes
// pinned for it (rug-pull defence).
//
// Two implementations: Memory, which is single-process and is what local runs
// and tests use, and Redis, which is the shared, TTL-bounded store DESIGN §5
// and decision 2 call for when the inspector runs more than one replica.
package session

import (
	"context"
	"sync"
	"time"
)

// Store keeps per-session taint and tool-definition pins. All entries are
// TTL-bounded; a zero ttl means "no expiry".
type Store interface {
	// Tainted reports whether the session is currently tainted.
	Tainted(ctx context.Context, session string) (bool, error)
	// Taint marks the session tainted for ttl.
	Taint(ctx context.Context, session string, ttl time.Duration) error
	// ToolPin returns the pinned definition hash for a tool, and whether one exists.
	ToolPin(ctx context.Context, session, tool string) (string, bool, error)
	// PinTool records the definition hash of a tool for ttl.
	PinTool(ctx context.Context, session, tool, hash string, ttl time.Duration) error
}

type entry struct {
	value     string
	expiresAt time.Time
}

func (e entry) live(now time.Time) bool {
	return e.expiresAt.IsZero() || e.expiresAt.After(now)
}

// Memory is an in-process Store. Safe for concurrent use.
type Memory struct {
	mu    sync.Mutex
	now   func() time.Time
	taint map[string]entry
	pins  map[string]entry // key: session + "\x00" + tool
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{now: time.Now, taint: map[string]entry{}, pins: map[string]entry{}}
}

func expiry(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return now.Add(ttl)
}

func (m *Memory) Tainted(_ context.Context, session string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.taint[session]
	if !ok {
		return false, nil
	}
	if !e.live(m.now()) {
		delete(m.taint, session)
		return false, nil
	}
	return true, nil
}

func (m *Memory) Taint(_ context.Context, session string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.taint[session] = entry{expiresAt: expiry(m.now(), ttl)}
	return nil
}

func (m *Memory) ToolPin(_ context.Context, session, tool string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := session + "\x00" + tool
	e, ok := m.pins[k]
	if !ok {
		return "", false, nil
	}
	if !e.live(m.now()) {
		delete(m.pins, k)
		return "", false, nil
	}
	return e.value, true, nil
}

func (m *Memory) PinTool(_ context.Context, session, tool, hash string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pins[session+"\x00"+tool] = entry{value: hash, expiresAt: expiry(m.now(), ttl)}
	return nil
}

var _ Store = (*Memory)(nil)
