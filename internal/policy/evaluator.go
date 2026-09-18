package policy

import (
	"context"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// Evaluator decides an action from findings and session state. It implements
// core.Evaluator.
type Evaluator struct {
	policy *Policy
}

// NewEvaluator returns an evaluator over p. A nil policy uses Default().
func NewEvaluator(p *Policy) *Evaluator {
	if p == nil {
		p = Default()
	}
	return &Evaluator{policy: p}
}

var _ core.Evaluator = (*Evaluator)(nil)

// Policy returns the policy in force.
func (e *Evaluator) Policy() *Policy { return e.policy }

// Evaluate is pass-through in Phase 0: every hop is allowed and the policy
// version is stamped on the verdict.
//
// TODO(phase-1): match e.policy.Rules against in.Request.Surface, in.Findings
// and in.SessionTainted, and take the most severe matching action
// (core.MostSevere) with taint_session OR-ed across matches — DESIGN §3.3, §3.6.
func (e *Evaluator) Evaluate(_ context.Context, _ core.EvalInput) (core.Decision, error) {
	return core.Decision{Action: core.ActionAllow, PolicyVersion: e.policy.Version}, nil
}

// OnError applies defaults.on_error (DESIGN §3.6).
func (e *Evaluator) OnError(_ core.EvalInput, _ error) core.Decision {
	return core.Decision{
		Action:        e.policy.Defaults.OnError.Action(),
		PolicyVersion: e.policy.Version,
	}
}
