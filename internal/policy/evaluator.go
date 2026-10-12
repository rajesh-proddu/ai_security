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

// Evaluate applies every rule and combines the ones that match: the most severe
// action wins (DESIGN §3.3), taint_session is OR-ed across matches, and the
// redaction spans are those of the findings selected by a redact rule.
//
// A policy with no matching rule allows the hop. Findings on their own never
// decide anything — only a rule does.
func (e *Evaluator) Evaluate(_ context.Context, in core.EvalInput) (core.Decision, error) {
	d := core.Decision{Action: core.ActionAllow, PolicyVersion: e.policy.Version}
	var actions []core.Action
	for _, rule := range e.policy.Rules {
		matched, spans := rule.match(in)
		if !matched {
			continue
		}
		actions = append(actions, rule.Action)
		if rule.TaintSession {
			d.TaintSession = true
		}
		if rule.Action == core.ActionRedact {
			d.Redactions = append(d.Redactions, spans...)
		}
	}
	d.Action = core.MostSevere(actions...)
	return d, nil
}

// OnError applies defaults.on_error (DESIGN §3.6).
func (e *Evaluator) OnError(_ core.EvalInput, _ error) core.Decision {
	return core.Decision{
		Action:        e.policy.Defaults.OnError.Action(),
		PolicyVersion: e.policy.Version,
	}
}
