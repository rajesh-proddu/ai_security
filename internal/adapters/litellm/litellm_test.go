package litellm

import (
	"context"
	"testing"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

type stubInspector struct{ saw core.Request }

func (s *stubInspector) Inspect(_ context.Context, req core.Request) (core.Verdict, error) {
	s.saw = req
	return core.Verdict{Action: core.ActionAllow}, nil
}

// The hook → surface mapping of DESIGN §3.2.
func TestHookSurfaces(t *testing.T) {
	tests := []struct {
		name string
		call func(*Guard, context.Context, core.Request) (core.Verdict, error)
		want core.Surface
	}{
		{"pre_call", (*Guard).PreCall, core.SurfaceInput},
		{"during_call", (*Guard).DuringCall, core.SurfaceInput},
		{"post_call", (*Guard).PostCall, core.SurfaceOutput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := &stubInspector{}
			// A surface set by the caller must not survive: the hook decides it.
			if _, err := tt.call(New(in), context.Background(), core.Request{Surface: core.SurfaceToolCall}); err != nil {
				t.Fatal(err)
			}
			if in.saw.Surface != tt.want {
				t.Fatalf("surface = %q, want %q", in.saw.Surface, tt.want)
			}
		})
	}
}
