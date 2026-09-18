package session

import (
	"context"
	"testing"
	"time"
)

func TestMemoryTaint(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		ttl     time.Duration
		advance time.Duration
		want    bool
	}{
		{"within ttl", time.Minute, 30 * time.Second, true},
		{"expired", time.Minute, 2 * time.Minute, false},
		{"exactly at expiry", time.Minute, time.Minute, false},
		{"no expiry", 0, 100 * time.Hour, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMemory()
			clock := now
			m.now = func() time.Time { return clock }

			if err := m.Taint(ctx, "s1", tt.ttl); err != nil {
				t.Fatal(err)
			}
			clock = clock.Add(tt.advance)

			got, err := m.Tainted(ctx, "s1")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("tainted = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMemoryUnknownSessionIsClean(t *testing.T) {
	got, err := NewMemory().Tainted(context.Background(), "never-seen")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("an unknown session must not be tainted")
	}
}

func TestMemoryToolPins(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }

	if _, ok, err := m.ToolPin(ctx, "s1", "email.send"); err != nil || ok {
		t.Fatalf("unpinned tool: ok = %v, err = %v", ok, err)
	}
	if err := m.PinTool(ctx, "s1", "email.send", "sha256:abc", time.Minute); err != nil {
		t.Fatal(err)
	}

	hash, ok, err := m.ToolPin(ctx, "s1", "email.send")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || hash != "sha256:abc" {
		t.Fatalf("pin = %q, ok = %v", hash, ok)
	}

	// Pins are per session and per tool.
	if _, ok, _ := m.ToolPin(ctx, "s2", "email.send"); ok {
		t.Error("a pin must not leak across sessions")
	}
	if _, ok, _ := m.ToolPin(ctx, "s1", "email.read"); ok {
		t.Error("a pin must not leak across tools")
	}

	clock = clock.Add(2 * time.Minute)
	if _, ok, _ := m.ToolPin(ctx, "s1", "email.send"); ok {
		t.Error("an expired pin must not be returned")
	}
}
