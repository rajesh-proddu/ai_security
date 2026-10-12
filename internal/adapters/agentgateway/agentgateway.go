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

import (
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/rajesh-proddu/ai_security/internal/adapters/agentgateway/extmcppb"
	"github.com/rajesh-proddu/ai_security/internal/core"
)

// MaxMessageSize bounds one gRPC message. ExtMcp sends a whole tools/call or
// resources/read result in a single message, and gRPC's 4 MiB default would
// reject a large one (an image, a long document); the gateway then fails the
// call closed. Request and response bodies on the LLM route are buffered up to
// end of stream, so this does not bound those.
const MaxMessageSize = 32 << 20

// ServerOptions are the gRPC server options the two protocols need.
func ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{grpc.MaxRecvMsgSize(MaxMessageSize), grpc.MaxSendMsgSize(MaxMessageSize)}
}

// Register serves both protocols on s.
func Register(s *grpc.Server, in core.Inspector) {
	extproc.RegisterExternalProcessorServer(s, NewLLM(in))
	extmcppb.RegisterExtMcpServer(s, NewMCP(in))
}
