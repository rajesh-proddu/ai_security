// Package audit emits one event per inspected hop (DESIGN §3.8).
//
// Retention rule (DESIGN §3.7, decision 5): metadata and hashes only. [Event]
// deliberately has no field for prompt or response bodies, so a body cannot be
// written by accident. Opt-in per-route body capture is Phase 3, and will be a
// separate, explicitly named path.
package audit

import "context"

// Finding is the metadata-only projection of a core finding. Spans are offsets,
// not content, so they are safe to record.
type Finding struct {
	Detector string  `json:"detector"`
	Type     string  `json:"type,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Part     int     `json:"part"`
	Start    int     `json:"start"`
	End      int     `json:"end"`
}

// Event is one inspected hop.
type Event struct {
	Time string `json:"time"`
	// TraceID ties events of one agent transaction together (DESIGN §3.8).
	// TODO(phase-1): populate from the OTel span context carried on ctx.
	TraceID       string    `json:"trace_id,omitempty"`
	SessionID     string    `json:"session_id,omitempty"`
	Surface       string    `json:"surface"`
	Caller        string    `json:"caller,omitempty"`
	Source        string    `json:"source,omitempty"`
	Action        string    `json:"action"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	TaintSession  bool      `json:"taint_session,omitempty"`
	Findings      []Finding `json:"findings,omitempty"`
	// ContentHash identifies the inspected payload without carrying it.
	ContentHash string  `json:"content_hash,omitempty"`
	LatencyMS   float64 `json:"latency_ms"`
	Error       string  `json:"error,omitempty"`
}

// Sink receives audit events. Implementations must be safe for concurrent use.
type Sink interface {
	Write(ctx context.Context, e Event) error
}
