// Package agentgateway is the v1 primary adapter (DESIGN §3.2): agentgateway
// calls this service over ext_proc — Envoy's external processing gRPC protocol
// — on LLM routes and MCP routes.
//
// Phase 0 ships no wire types on purpose. The ext_proc message shapes, and what
// agentgateway actually puts in them on MCP routes, are the first item of
// ROADMAP Phase 1 ("Spike first"), and this repo does not guess at protocols it
// has not exercised. No protobuf, gRPC or go-control-plane dependency is added
// until the spike lands.
//
// Phase 1 spike items, from ROADMAP Phase 1 and DESIGN §3.2:
//
//  1. The ext_proc payloads on LLM routes and on MCP routes — in particular
//     whether the MCP tool name and arguments arrive as request body JSON or as
//     separate metadata.
//  2. Body mutation (for redaction) and immediate response (for block) from the
//     body phases, including in streamed body mode (DESIGN §3.5).
//  3. The gateway's `failureMode` setting, which must match the policy's
//     defaults.on_error; a mismatch is an alert (DESIGN §4).
//  4. Whether agentgateway already pins tool definitions. If it does, v1
//     consumes its signal instead of implementing pinning here (DESIGN §2).
//
// References (read these, do not infer the format):
//   - Envoy ext_proc: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter
//   - agentgateway: https://agentgateway.dev/docs/
package agentgateway

import "github.com/rajesh-proddu/ai_security/internal/core"

// Processor is the Phase 1 ext_proc server: gateway-neutral inspection plus
// whatever the spike shows the protocol needs.
//
// TODO(phase-1): give Processor the generated ExternalProcessor server methods,
// mapping each stream phase to a core.Surface and each core.Verdict to a
// continue / body-mutation / immediate-response reply.
type Processor struct {
	Inspector core.Inspector
}

// New returns a Processor over the given inspector.
func New(in core.Inspector) *Processor { return &Processor{Inspector: in} }
