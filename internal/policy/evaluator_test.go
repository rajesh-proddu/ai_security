package policy

import (
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

func TestNewEvaluatorNilPolicy(t *testing.T) {
	e := NewEvaluator(nil)
	if e.Policy().Defaults.OnError != FailClosed {
		t.Fatal("a nil policy must default to fail_closed")
	}
}
