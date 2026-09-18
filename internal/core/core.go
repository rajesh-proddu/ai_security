// Package core is the gateway-neutral inspection surface described in DESIGN §3.1.
// It must not import any gateway package; adapters translate wire formats into
// [Request] and a [Verdict] back into the gateway's response.
package core

import "context"

// Surface is one of the four inspected hops (DESIGN §2, §3.6).
type Surface string

const (
	SurfaceInput      Surface = "input"
	SurfaceToolCall   Surface = "tool_call"
	SurfaceToolResult Surface = "tool_result"
	SurfaceOutput     Surface = "output"
)

// Trust marks whether a part came from a source that may carry attacker-controlled
// instructions (tool results, RAG content) — DESIGN §3.4.
type Trust string

const (
	TrustTrusted   Trust = "trusted"
	TrustUntrusted Trust = "untrusted"
)

// Action is the decision for an inspected hop. Ordered least to most severe;
// "most severe wins" when several rules match (DESIGN §3.3).
type Action string

const (
	ActionAllow  Action = "allow"
	ActionFlag   Action = "flag"
	ActionRedact Action = "redact"
	ActionBlock  Action = "block"
)

// Severity orders actions. Unknown actions sort below allow so that a malformed
// policy value can never be more severe than an explicit decision.
func (a Action) Severity() int {
	switch a {
	case ActionAllow:
		return 0
	case ActionFlag:
		return 1
	case ActionRedact:
		return 2
	case ActionBlock:
		return 3
	default:
		return -1
	}
}

// MostSevere returns the highest-severity action, or ActionAllow if none are given.
func MostSevere(actions ...Action) Action {
	worst := ActionAllow
	for _, a := range actions {
		if a.Severity() > worst.Severity() {
			worst = a
		}
	}
	return worst
}

// Span locates a byte range inside Request.Parts[Part].Text.
type Span struct {
	Part  int
	Start int
	End   int
}

// Finding is one detector hit: type, span, score and the detector that produced it.
type Finding struct {
	Detector string
	Type     string
	Span     Span
	Score    float64
}

// Part is one piece of the payload being inspected.
type Part struct {
	Role  string
	Text  string
	Trust Trust
}

// Request is the single input to [Inspector]. Source is the model, tool name,
// MCP server or retriever the content belongs to.
type Request struct {
	Surface Surface
	Session string
	Caller  string
	Source  string
	Parts   []Part
}

// Verdict is the single output of [Inspector].
type Verdict struct {
	Action        Action
	Findings      []Finding
	Redactions    []Span
	TaintSession  bool
	PolicyVersion string
}

// Inspector is the one operation the core exposes (DESIGN §3.1).
type Inspector interface {
	Inspect(ctx context.Context, req Request) (Verdict, error)
}
