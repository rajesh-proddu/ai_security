package agentgateway

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/rajesh-proddu/ai_security/internal/adapters/agentgateway/extmcppb"
	"github.com/rajesh-proddu/ai_security/internal/core"
)

// MCP serves agentgateway's ExtMcp protocol: the `mcpGuardrails` policy on MCP
// routes (DESIGN §3.2). It sees each MCP method's `params` before the call goes
// upstream and its `result` before it reaches the agent, as JSON.
//
// Methods inspected:
//
//	tools/list     result → tool_definition, one inspection per tool. A blocked
//	               tool is removed from the list (and, in core, from the session).
//	tools/call     params → tool_call; result → tool_result.
//	resources/read result → tool_result.
//
// Every other method passes. Notifications never reach this hook.
//
// Scope limit (Phase 1): tool state is keyed by session and tool name, without
// the MCP server. Two servers behind one gateway that expose the same tool name
// share pins and blocks.
type MCP struct {
	extmcppb.UnimplementedExtMcpServer
	Inspector core.Inspector
}

// NewMCP returns an ExtMcp server over the given inspector.
func NewMCP(in core.Inspector) *MCP { return &MCP{Inspector: in} }

const (
	methodToolsList     = "tools/list"
	methodToolsCall     = "tools/call"
	methodResourcesRead = "resources/read"
)

// The reason reaches the agent as a JSON-RPC error, so it never names what
// matched.
const blockedReason = "blocked by ai_security policy"

var (
	pass   = &extmcppb.McpRequestResult{Result: &extmcppb.McpRequestResult_Pass{Pass: &extmcppb.Pass{}}}
	passed = &extmcppb.McpResponseResult{Result: &extmcppb.McpResponseResult_Pass{Pass: &extmcppb.Pass{}}}
)

func deniedRequest() *extmcppb.McpRequestResult {
	return &extmcppb.McpRequestResult{Result: &extmcppb.McpRequestResult_Error{Error: &extmcppb.AuthorizationError{
		Code: extmcppb.AuthorizationError_PERMISSION_DENIED, Reason: blockedReason}}}
}

func deniedResponse() *extmcppb.McpResponseResult {
	return &extmcppb.McpResponseResult{Result: &extmcppb.McpResponseResult_Error{Error: &extmcppb.AuthorizationError{
		Code: extmcppb.AuthorizationError_PERMISSION_DENIED, Reason: blockedReason}}}
}

func (m *MCP) CheckRequest(ctx context.Context, r *extmcppb.McpRequest) (*extmcppb.McpRequestResult, error) {
	if r.GetMethod() != methodToolsCall || len(r.GetMcpRequest()) == 0 {
		return pass, nil
	}
	v, err := decodeJSON(r.GetMcpRequest())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tools/call params: %v", err)
	}
	params, _ := v.(map[string]any)
	name, _ := params["name"].(string)

	var fields []textField
	stringLeaves(params["arguments"], &fields)
	req := core.Request{
		Surface: core.SurfaceToolCall,
		Session: requestSession(r.GetMetadataContext(), r.GetHeaders()),
		Source:  name,
		Parts:   parts(fields, "tool", core.TrustTrusted),
	}
	verdict, err := m.Inspector.Inspect(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "inspect: %v", err)
	}
	switch verdict.Action {
	case core.ActionBlock:
		return deniedRequest(), nil
	case core.ActionRedact:
		if !redactFields(fields, verdict.Redactions) {
			return pass, nil
		}
		b, err := encodeJSON(params)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encode params: %v", err)
		}
		return &extmcppb.McpRequestResult{Result: &extmcppb.McpRequestResult_Mutated{Mutated: b}}, nil
	}
	return pass, nil
}

func (m *MCP) CheckResponse(ctx context.Context, r *extmcppb.McpResponse) (*extmcppb.McpResponseResult, error) {
	switch r.GetMethod() {
	case methodToolsList, methodToolsCall, methodResourcesRead:
	default:
		return passed, nil
	}
	v, err := decodeJSON(r.GetMcpResponse())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s result: %v", r.GetMethod(), err)
	}
	result, _ := v.(map[string]any)
	sess := responseSession(r.GetMetadataContext())

	var changed bool
	if r.GetMethod() == methodToolsList {
		changed, err = m.toolsList(ctx, result, sess, r.GetServiceNames())
		if err != nil {
			return nil, err
		}
	} else {
		var blocked bool
		blocked, changed, err = m.toolResult(ctx, result, sess, r.GetServiceNames())
		if err != nil {
			return nil, err
		}
		if blocked {
			return deniedResponse(), nil
		}
	}
	if !changed {
		return passed, nil
	}
	b, err := encodeJSON(result)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode result: %v", err)
	}
	return &extmcppb.McpResponseResult{Result: &extmcppb.McpResponseResult_Mutated{Mutated: b}}, nil
}

// toolsList inspects each tool definition on its own, so one poisoned tool is
// removed without hiding the rest. It reports whether the list changed.
func (m *MCP) toolsList(ctx context.Context, result map[string]any, sess string, services []string) (bool, error) {
	tools, _ := result["tools"].([]any)
	kept := make([]any, 0, len(tools))
	changed := false
	for _, t := range tools {
		tool, ok := t.(map[string]any)
		if !ok {
			kept = append(kept, t)
			continue
		}
		name, _ := tool["name"].(string)
		var fields []textField
		stringLeaves(tool, &fields)
		verdict, err := m.Inspector.Inspect(ctx, core.Request{
			Surface: core.SurfaceToolDefinition,
			Session: sess,
			Source:  nativeToolName(name, services),
			Parts:   parts(fields, "tool", core.TrustUntrusted),
		})
		if err != nil {
			return false, status.Errorf(codes.Internal, "inspect: %v", err)
		}
		switch verdict.Action {
		case core.ActionBlock:
			changed = true
			continue
		case core.ActionRedact:
			if redactFields(fields, verdict.Redactions) {
				changed = true
			}
		}
		kept = append(kept, tool)
	}
	if changed {
		result["tools"] = kept
	}
	return changed, nil
}

// toolResult inspects the text a tools/call or resources/read result carries.
// Binary content (image and audio data, resource blobs) is skipped: it is not
// text, and base64 trips the entropy and encoded-payload detectors.
func (m *MCP) toolResult(ctx context.Context, result map[string]any, sess string, services []string) (blocked, changed bool, err error) {
	var fields []textField
	// tools/call: content[].text, content[].resource.text, structuredContent.
	// resources/read: contents[].text.
	for _, key := range []string{"content", "contents"} {
		items, _ := result[key].([]any)
		for _, it := range items {
			item, ok := it.(map[string]any)
			if !ok {
				continue
			}
			if f, ok := stringField(item, "text"); ok {
				fields = append(fields, f)
			}
			if res, ok := item["resource"].(map[string]any); ok {
				if f, ok := stringField(res, "text"); ok {
					fields = append(fields, f)
				}
			}
		}
	}
	stringLeaves(result["structuredContent"], &fields)
	if len(fields) == 0 {
		return false, false, nil
	}

	// The response names no tool, only the server it came from.
	source := ""
	if len(services) == 1 {
		source = services[0]
	}
	verdict, err := m.Inspector.Inspect(ctx, core.Request{
		Surface: core.SurfaceToolResult,
		Session: sess,
		Source:  source,
		Parts:   parts(fields, "tool", core.TrustUntrusted),
	})
	if err != nil {
		return false, false, status.Errorf(codes.Internal, "inspect: %v", err)
	}
	switch verdict.Action {
	case core.ActionBlock:
		return true, false, nil
	case core.ActionRedact:
		return false, redactFields(fields, verdict.Redactions), nil
	}
	return false, false, nil
}

// nativeToolName undoes agentgateway's multiplexing. With more than one MCP
// server behind a route, tools/list names are `<server>_<tool>`, while
// tools/call carries the bare tool name and the server separately; with one
// server both use the bare name. Pins and blocks are keyed by the bare name so
// the two methods agree.
func nativeToolName(name string, services []string) string {
	if len(services) < 2 {
		return name
	}
	for _, s := range services {
		if rest, ok := strings.CutPrefix(name, s+"_"); ok {
			return rest
		}
	}
	return name
}

// Session identity follows DESIGN §6 decision 2: the agent's x-session-id
// first, then MCP's Mcp-Session-Id, then the W3C trace id.
//
// Requests carry headers; responses do not, so on the response side the
// session comes only from metadata_context, which the gateway fills from the
// request headers by CEL (ai_platform gateway/config.yaml): `session` from
// x-session-id and `mcp_session` from mcp-session-id. Without the second key,
// an agent that sends no x-session-id would have its tool calls checked under
// one session and its tool lists and results recorded under none.
const (
	metadataSessionKey    = "session"
	metadataMCPSessionKey = "mcp_session"
)

func metadataString(md *structpb.Struct, key string) string {
	if md == nil {
		return ""
	}
	return md.GetFields()[key].GetStringValue()
}

func responseSession(md *structpb.Struct) string {
	if s := metadataString(md, metadataSessionKey); s != "" {
		return s
	}
	return metadataString(md, metadataMCPSessionKey)
}

func requestSession(md *structpb.Struct, headers []*extmcppb.McpHeader) string {
	if s := metadataString(md, metadataSessionKey); s != "" {
		return s
	}
	get := func(key string) string {
		for _, h := range headers {
			if strings.EqualFold(h.GetKey(), key) {
				return string(h.GetValue())
			}
		}
		return ""
	}
	return sessionFrom(get)
}

// sessionFrom applies the decision 2 order to a header lookup.
func sessionFrom(header func(string) string) string {
	if s := header("x-session-id"); s != "" {
		return s
	}
	if s := header("mcp-session-id"); s != "" {
		return s
	}
	return traceID(header("traceparent"))
}

// traceID extracts the trace id from a W3C traceparent
// (version-traceid-parentid-flags).
func traceID(traceparent string) string {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 || len(parts[1]) != 32 {
		return ""
	}
	return parts[1]
}
