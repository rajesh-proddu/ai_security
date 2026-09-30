// Package agentgateway is the v1 primary adapter (DESIGN §3.2). agentgateway
// calls this service over two gRPC protocols on one listener (:9000):
//
//   - LLM routes: ext_proc, Envoy's external processing protocol, with body mode
//     fullDuplexStreamed. Every body chunk must be sent back as a streamed body
//     mutation; a reply without one empties the body.
//   - MCP routes: agentgateway's ExtMcp service (the mcpGuardrails policy), which
//     carries the MCP method, params and result as JSON, and the session in
//     metadata_context.
//
// The wire behaviour this relies on was observed in the Phase 1 spike
// (docs/spikes/agentgateway-extproc.md); captured messages are in testdata/.
//
// References:
//   - Envoy ext_proc: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter
//   - ExtMcp: crates/protos/proto/ext_mcp.proto in https://github.com/agentgateway/agentgateway
package agentgateway

import "github.com/rajesh-proddu/ai_security/internal/core"

// Processor is the Phase 1 gRPC server for both protocols.
//
// TODO(phase-1): give Processor the ExternalProcessor and ExtMcp server
// methods, mapping each ext_proc stream phase and each MCP method to a
// core.Surface, and each core.Verdict to a streamed body mutation or immediate
// response (ext_proc) or a pass / mutated / reject result (ExtMcp).
type Processor struct {
	Inspector core.Inspector
}

// New returns a Processor over the given inspector.
func New(in core.Inspector) *Processor { return &Processor{Inspector: in} }
