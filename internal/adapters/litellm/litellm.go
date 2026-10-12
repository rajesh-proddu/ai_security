// Package litellm is the swap-proof adapter (DESIGN §3.2): LiteLLM calls this
// service through its Generic Guardrail API, which has three hooks —
// `pre_call` (input), `during_call` (input, concurrent with the model call) and
// `post_call` (output).
//
// The hook triad is fixed by the design; the JSON bodies LiteLLM sends are not
// verified here, so Phase 0 ships the hook-to-surface mapping and no wire
// structs.
//
// Phase 2 spike items, from ROADMAP Phase 2 and DESIGN §3.2, §3.5:
//
//  1. The request and response JSON of each hook, and how a guardrail signals
//     "block" versus "return this modified body".
//  2. Whether the guardrail API sees stream chunks or only the assembled
//     response. If only the latter, streamed routes on LiteLLM get post-hoc
//     flagging, not redaction (DESIGN §3.5).
//  3. `unreachable_fallback: fail_closed` — confirm it is honoured, and that it
//     matches the policy's defaults.on_error.
//
// Known coverage gap, stated not hidden (DESIGN §3.2): LiteLLM has no MCP
// tool-call hook on this path, so tool-call and tool-result coverage is weaker
// than on agentgateway. Tool results are only seen when the agent sends them as
// `tool` messages.
//
// Reference: https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail
package litellm

import (
	"context"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// Guard maps LiteLLM's three guardrail hooks onto core surfaces.
//
// TODO(phase-2): add the HTTP handler that decodes each hook's body into
// core.Request and encodes the verdict into LiteLLM's guardrail response.
type Guard struct {
	Inspector core.Inspector
}

// New returns a Guard over the given inspector.
func New(in core.Inspector) *Guard { return &Guard{Inspector: in} }

// PreCall inspects the input before the model call.
func (g *Guard) PreCall(ctx context.Context, req core.Request) (core.Verdict, error) {
	req.Surface = core.SurfaceInput
	return g.Inspector.Inspect(ctx, req)
}

// DuringCall inspects the input concurrently with the model call. This is where
// `injection_ml` runs on LiteLLM, so its latency is hidden by the model call
// (DESIGN §3.3).
func (g *Guard) DuringCall(ctx context.Context, req core.Request) (core.Verdict, error) {
	req.Surface = core.SurfaceInput
	return g.Inspector.Inspect(ctx, req)
}

// PostCall inspects the model output.
func (g *Guard) PostCall(ctx context.Context, req core.Request) (core.Verdict, error) {
	req.Surface = core.SurfaceOutput
	return g.Inspector.Inspect(ctx, req)
}
