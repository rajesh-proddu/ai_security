package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

func TestOnError(t *testing.T) {
	tests := []struct {
		name    string
		onError OnError
		want    core.Action
	}{
		{"fail_closed blocks", FailClosed, core.ActionBlock},
		{"fail_open allows", FailOpen, core.ActionAllow},
		{"unset fails closed", OnError(""), core.ActionBlock},
		{"misspelled fails closed", OnError("fail-open"), core.ActionBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(&Policy{Defaults: Defaults{OnError: tt.onError}, Version: "v"})
			got := e.OnError(core.EvalInput{}, errors.New("detector down"))
			if got.Action != tt.want {
				t.Errorf("action = %s, want %s", got.Action, tt.want)
			}
			if got.PolicyVersion != "v" {
				t.Errorf("policy version = %q, want v", got.PolicyVersion)
			}
		})
	}
}

// Phase 0 keeps the evaluator a pass-through; rule matching is Phase 1.
func TestEvaluateIsPassThrough(t *testing.T) {
	p, err := LoadFile("testdata/example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEvaluator(p)
	got, err := e.Evaluate(context.Background(), core.EvalInput{
		Request:        core.Request{Surface: core.SurfaceToolResult},
		Findings:       []core.Finding{{Detector: "injection_heuristic"}},
		SessionTainted: true,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Action != core.ActionAllow {
		t.Errorf("action = %s, want allow", got.Action)
	}
	if got.PolicyVersion != p.Version {
		t.Errorf("policy version = %q, want %q", got.PolicyVersion, p.Version)
	}
}

func TestNewEvaluatorNilPolicy(t *testing.T) {
	e := NewEvaluator(nil)
	if e.Policy().Defaults.OnError != FailClosed {
		t.Fatal("a nil policy must default to fail_closed")
	}
}
