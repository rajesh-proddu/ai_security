// Package policy is the declarative rule table of DESIGN §3.6 and the small
// evaluator that v1 keeps instead of OPA/Rego.
package policy

import (
	"fmt"

	"github.com/rajesh-proddu/ai_security/internal/core"
	"gopkg.in/yaml.v3"
)

// OnError is the defaults.on_error behaviour: what a detector or ML failure
// means. fail_closed → block, fail_open → allow.
type OnError string

const (
	FailClosed OnError = "fail_closed"
	FailOpen   OnError = "fail_open"
)

// Action returns the action an on_error setting maps to. Anything other than an
// explicit fail_open blocks, so a missing or misspelled value fails closed.
func (o OnError) Action() core.Action {
	if o == FailOpen {
		return core.ActionAllow
	}
	return core.ActionBlock
}

// Policy is a parsed bundle.
//
// Version is derived by the loader from the bundle bytes and is not a YAML
// field, per DESIGN §3.6: it ties an audit event to the exact rules that
// produced it until the control plane issues versioned, signed bundles in
// Phase 3, which then supply the value without changing the field's shape.
type Policy struct {
	Tenant   string   `yaml:"tenant"`
	Defaults Defaults `yaml:"defaults"`
	Rules    []Rule   `yaml:"rules"`

	Version string `yaml:"-"`
}

// Defaults applies to every rule unless a rule overrides it.
type Defaults struct {
	OnError OnError `yaml:"on_error"`
}

// Rule maps a condition on one or more surfaces to an action. taint_session is
// a sibling of action, not part of the condition.
type Rule struct {
	Surface      StringList  `yaml:"surface"`
	When         Condition   `yaml:"when"`
	Action       core.Action `yaml:"action"`
	TaintSession bool        `yaml:"taint_session"`
}

// Condition is the `when` block. All set fields must match.
type Condition struct {
	Detector       StringList `yaml:"detector"`
	ScoreGTE       *float64   `yaml:"score_gte"`
	TypeIn         StringList `yaml:"type_in"`
	Tool           string     `yaml:"tool"`
	SessionTainted *bool      `yaml:"session_tainted"`
	// PinChanged matches a tool_definition whose hash differs from the one
	// approved earlier — the rug-pull case of DESIGN §4. Parsed in Phase 0;
	// the pin comparison itself is Phase 1.
	PinChanged *bool `yaml:"pin_changed"`
}

// StringList accepts either a scalar or a sequence: DESIGN §3.6 writes
// `detector: injection_ml` in one rule and `detector: [pii, secrets]` in another.
type StringList []string

func (l *StringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		*l = StringList{s}
		return nil
	case yaml.SequenceNode:
		var ss []string
		if err := value.Decode(&ss); err != nil {
			return err
		}
		*l = ss
		return nil
	default:
		return fmt.Errorf("policy: line %d: expected a string or a list of strings", value.Line)
	}
}

// Contains reports whether the list holds s. An empty list matches nothing;
// callers treat "unset" as "no constraint" before calling this.
func (l StringList) Contains(s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}
