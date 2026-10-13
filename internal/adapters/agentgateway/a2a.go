package agentgateway

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// A2A (agent-to-agent) traffic reaches the inspector through route-level
// ext_proc on routes carrying agentgateway's `a2a` policy; agentgateway has no
// A2A-specific hook (docs/spikes/agentgateway-extproc.md). A route declares
// itself in its ext_proc metadataContext:
//
//	metadataContext:
//	  ai_security:
//	    protocol: '"a2a"'
//	    agent: '"video-catalogue"'   # the remote agent's identity for policy
//	    direction: '"outbound"'      # or "inbound"; default outbound
//
// The agent's identity comes from this config, never from its card: the card
// is written by the remote agent, which could rename itself to escape a block.
// Policy `tool:` rules name A2A agents by this identity.
//
// Outbound (our agent calls a remote one), the hops map onto existing surfaces:
//
//	agent card                         → tool_definition (poisoned skills, pinning)
//	message/send, message/stream       → tool_call (what leaves; taint blocks it)
//	the remote agent's reply           → tool_result, untrusted (injection, taint)
//
// Inbound (a remote agent calls ours), the remote request is untrusted input
// and our reply is output; our own card is not inspected.
//
// Inspection goes by content, not by method name: every request's params and
// every JSON or SSE reply on the route is inspected, so an unlisted method, a
// JSON-RPC batch or a resubscribe stream cannot pass unseen. Parts are
// inspected whatever their `role`: the remote agent writes that field, and
// could label an injected reply `user` to escape. (The cost: our own earlier
// turns quoted back in a task's history are inspected too.)
//
// Both A2A versions are read: v0.3 (`message/send`, parts with `kind`) and
// v1.0 (`SendMessage`, parts discriminated by member). Text is taken from
// message parts only, never from every string: message, task and artifact ids
// are UUIDs that would trip the entropy detector.
const (
	metadataNamespace = "ai_security"
	a2aBlockCode      = -32000 // A2A reserves -32001..-32099
)

// a2aRoute is what an A2A route declared.
type a2aRoute struct {
	agent   string
	inbound bool
}

// routeMetadata reads the route's ai_security metadata.
func routeMetadata(md *corev3.Metadata) map[string]string {
	out := map[string]string{}
	st := md.GetFilterMetadata()[metadataNamespace]
	for k, v := range st.GetFields() {
		if s, ok := v.GetKind().(*structpb.Value_StringValue); ok {
			out[k] = s.StringValue
		}
	}
	return out
}

func isAgentCard(path string) bool {
	p, _, _ := strings.Cut(path, "?")
	return strings.HasSuffix(p, "/.well-known/agent-card.json") || strings.HasSuffix(p, "/.well-known/agent.json")
}

func isA2ASend(method string) bool {
	switch method {
	case "message/send", "message/stream", "SendMessage", "SendStreamingMessage":
		return true
	}
	return false
}

// isExtendedCard is the method that returns an authenticated agent card; its
// result is inspected as a card.
func isExtendedCard(method string) bool {
	return method == "GetExtendedAgentCard" || method == "agent/getAuthenticatedExtendedCard"
}

// a2aState is the per-exchange state of an A2A stream.
type a2aState struct {
	route  a2aRoute
	method string
	id     json.RawMessage // the JSON-RPC id, echoed in errors
}

// handleA2A processes one ext_proc message of an A2A exchange.
func (l *LLM) handleA2A(ctx context.Context, st *llmStream, msg *extproc.ProcessingRequest) ([]*extproc.ProcessingResponse, bool, error) {
	a := st.a2a
	switch r := msg.GetRequest().(type) {
	case *extproc.ProcessingRequest_RequestBody:
		st.reqBody = append(st.reqBody, r.RequestBody.GetBody()...)
		if !r.RequestBody.GetEndOfStream() {
			return nil, false, nil
		}
		body, blocked, err := l.a2aRequest(ctx, st)
		if err != nil {
			return nil, false, err
		}
		if blocked {
			return one(jsonRPCBlock(a.id)), true, nil
		}
		return one(requestBodyReply(body)), false, nil

	case *extproc.ProcessingRequest_ResponseHeaders:
		h := headerMap(r.ResponseHeaders.GetHeaders())
		hasBody := !r.ResponseHeaders.GetEndOfStream() && success(h[":status"])
		card := isAgentCard(st.path) && !a.route.inbound
		if hasBody && !card && isSSE(h["content-type"]) {
			surface, trust := a2aReplySurface(a.route)
			st.window = newStreamWindow(func(ctx context.Context, text string) (core.Verdict, error) {
				return l.Inspector.Inspect(ctx, core.Request{Surface: surface, Session: st.session, Source: a.route.agent,
					Parts: []core.Part{{Role: "agent", Text: text, Trust: trust}}})
			})
			st.window.extract = a2aStreamExtractor()
			st.window.blockBytes = []byte("data: " + string(jsonRPCErrorBody(a.id)) + "\n\n")
			return one(responseHeadersReply()), false, nil
		}
		st.inspectResponse = hasBody && isJSON(h["content-type"]) && (card || !isAgentCard(st.path))
		if st.inspectResponse {
			st.heldHeaders = true
			return nil, false, nil
		}
		return one(responseHeadersReply()), false, nil

	case *extproc.ProcessingRequest_ResponseBody:
		chunk := r.ResponseBody.GetBody()
		eos := r.ResponseBody.GetEndOfStream()
		if st.window != nil {
			out, reply, end, err := st.window.chunk(ctx, chunk, eos)
			if err != nil || !reply {
				return nil, false, err
			}
			return one(responseBodyReply(out, end)), false, nil
		}
		if !st.inspectResponse {
			return one(responseBodyReply(chunk, eos)), false, nil
		}
		st.respBody = append(st.respBody, chunk...)
		if !eos {
			return nil, false, nil
		}
		var body []byte
		var blocked bool
		var err error
		if isAgentCard(st.path) {
			body, blocked, err = l.a2aCard(ctx, st, nil)
			if blocked {
				return one(cardBlock()), true, err
			}
		} else if isExtendedCard(a.method) {
			body, blocked, err = l.a2aCard(ctx, st, []string{"result"})
			if blocked {
				return one(jsonRPCBlock(a.id)), true, err
			}
		} else {
			body, blocked, err = l.a2aReply(ctx, st)
			if blocked {
				return one(jsonRPCBlock(a.id)), true, err
			}
		}
		if err != nil {
			return nil, false, err
		}
		var out []*extproc.ProcessingResponse
		if st.heldHeaders {
			out = append(out, responseHeadersReply())
			st.heldHeaders = false
		}
		return append(out, responseBodyReply(body, true)), false, nil
	}
	return trailersReply(msg), false, nil
}

// a2aRequest inspects the message parts a request carries, whatever its
// method: outbound, what leaves for the remote agent (tool_call); inbound, the
// remote agent's request to ours (input, untrusted). A JSON-RPC batch is
// inspected as a whole. A request with no parts is inspected only if it sends
// a message, so reads such as tasks/get are not blocked by call rules.
func (l *LLM) a2aRequest(ctx context.Context, st *llmStream) ([]byte, bool, error) {
	a := st.a2a
	v, err := decodeJSON(st.reqBody)
	if err != nil {
		return st.reqBody, false, nil
	}
	calls, isBatch := v.([]any)
	if !isBatch {
		calls = []any{v}
	}
	sends := false
	var fields []textField
	for i, c := range calls {
		rpc, _ := c.(map[string]any)
		method, _ := rpc["method"].(string)
		if i == 0 {
			a.method = method
			if !isBatch {
				a.id, _ = json.Marshal(rpc["id"])
			}
		}
		sends = sends || isA2ASend(method)
		fields = append(fields, a2aParts(rpc["params"])...)
	}
	if len(fields) == 0 && !sends {
		return st.reqBody, false, nil
	}
	surface, trust := core.SurfaceToolCall, core.TrustTrusted
	if a.route.inbound {
		surface, trust = core.SurfaceInput, core.TrustUntrusted
	}
	verdict, err := l.Inspector.Inspect(ctx, core.Request{Surface: surface, Session: st.session, Source: a.route.agent,
		Parts: parts(fields, "user", trust)})
	if err != nil {
		return nil, false, err
	}
	switch verdict.Action {
	case core.ActionBlock:
		return nil, true, nil
	case core.ActionRedact:
		if redactFields(fields, verdict.Redactions) {
			b, err := encodeJSON(v)
			return b, false, err
		}
	}
	return st.reqBody, false, nil
}

func a2aReplySurface(r a2aRoute) (core.Surface, core.Trust) {
	if r.inbound {
		return core.SurfaceOutput, core.TrustTrusted
	}
	return core.SurfaceToolResult, core.TrustUntrusted
}

// a2aReply inspects a JSON-RPC result: a Message, a Task (its artifacts, status
// message and the agent's turns in its history), or an error, which passes.
func (l *LLM) a2aReply(ctx context.Context, st *llmStream) ([]byte, bool, error) {
	v, err := decodeJSON(st.respBody)
	if err != nil {
		return st.respBody, false, nil
	}
	fields := a2aParts(v)
	if len(fields) == 0 {
		return st.respBody, false, nil
	}
	surface, trust := a2aReplySurface(st.a2a.route)
	verdict, err := l.Inspector.Inspect(ctx, core.Request{Surface: surface, Session: st.session, Source: st.a2a.route.agent,
		Parts: parts(fields, "agent", trust)})
	if err != nil {
		return nil, false, err
	}
	switch verdict.Action {
	case core.ActionBlock:
		return nil, true, nil
	case core.ActionRedact:
		if redactFields(fields, verdict.Redactions) {
			b, err := encodeJSON(v)
			return b, false, err
		}
	}
	return st.respBody, false, nil
}

// a2aCard inspects a remote agent's card as a tool definition, keyed by the
// route's agent identity so pins and blocks follow the configured agent. The
// URLs the gateway rewrites (url, supportedInterfaces[].url) are left out:
// they depend on how the client reached the gateway, and would look like a
// rug pull from a second hostname.
//
// at is where the card sits in the body: nil for a card fetch, ["result"] for
// the extended-card method.
func (l *LLM) a2aCard(ctx context.Context, st *llmStream, at []string) ([]byte, bool, error) {
	v, err := decodeJSON(st.respBody)
	if err != nil {
		return st.respBody, false, nil
	}
	cardValue := v
	for _, k := range at {
		m, _ := cardValue.(map[string]any)
		cardValue = m[k]
	}
	card, ok := cardValue.(map[string]any)
	if !ok {
		return st.respBody, false, nil
	}
	restore := stripCardURLs(card)
	var fields []textField
	stringLeaves(card, &fields)
	verdict, err := l.Inspector.Inspect(ctx, core.Request{Surface: core.SurfaceToolDefinition, Session: st.session,
		Source: st.a2a.route.agent, Parts: parts(fields, "agent_card", core.TrustUntrusted)})
	if err != nil {
		return nil, false, err
	}
	switch verdict.Action {
	case core.ActionBlock:
		return nil, true, nil
	case core.ActionRedact:
		if redactFields(fields, verdict.Redactions) {
			restore()
			b, err := encodeJSON(v)
			return b, false, err
		}
	}
	return st.respBody, false, nil
}

// stripCardURLs removes the URL fields the gateway rewrites and returns a
// function that puts them back.
func stripCardURLs(card map[string]any) func() {
	var undo []func()
	if u, ok := card["url"]; ok {
		delete(card, "url")
		undo = append(undo, func() { card["url"] = u })
	}
	ifaces, _ := card["supportedInterfaces"].([]any)
	for _, it := range ifaces {
		iface, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if u, ok := iface["url"]; ok {
			delete(iface, "url")
			undo = append(undo, func() { iface["url"] = u })
		}
	}
	return func() {
		for _, f := range undo {
			f()
		}
	}
}

// a2aParts collects the text of every message part under v, whatever the
// message's role: text parts, the string values of data parts, and file URLs
// (not file bytes).
func a2aParts(v any) []textField {
	var out []textField
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if ps, ok := t["parts"].([]any); ok {
				for _, p := range ps {
					out = append(out, partText(p)...)
				}
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				if k != "parts" {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys) // a stable order, as in stringLeaves
			for _, k := range keys {
				walk(t[k])
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(v)
	return out
}

// partText reads one A2A part, v0.3 (`kind`) or v1.0 (member present).
func partText(p any) []textField {
	part, ok := p.(map[string]any)
	if !ok {
		return nil
	}
	var out []textField
	if f, ok := stringField(part, "text"); ok {
		out = append(out, f)
	}
	if d, ok := part["data"]; ok {
		if _, isString := d.(string); !isString { // v0.3 data parts hold JSON; strings here are base64
			stringLeaves(d, &out)
		}
	}
	if f, ok := stringField(part, "url"); ok { // v1.0 file by reference
		out = append(out, f)
	}
	if file, ok := part["file"].(map[string]any); ok { // v0.3 file
		if f, ok := stringField(file, "uri"); ok {
			out = append(out, f)
		}
	}
	return out
}

// a2aStreamExtractor finds the text in A2A streaming events (JSON-RPC
// envelopes). Artifact chunks are windowed per artifact; an update with
// append=false replaces the artifact, so it starts a new stream. Text that
// arrives whole (a status message, a full message or task) is complete.
func a2aStreamExtractor() func(any) []streamField {
	generation := map[string]int{}
	return func(data any) []streamField {
		rpc, _ := data.(map[string]any)
		res, _ := rpc["result"].(map[string]any)
		if res == nil {
			return nil
		}
		// v1.0 wraps events: {"artifactUpdate": {...}}, {"statusUpdate": {...}}.
		kind, _ := res["kind"].(string)
		if u, ok := res["artifactUpdate"].(map[string]any); ok {
			res, kind = u, "artifact-update"
		} else if u, ok := res["statusUpdate"].(map[string]any); ok {
			res, kind = u, "status-update"
		}
		var out []streamField
		if kind == "artifact-update" {
			art, _ := res["artifact"].(map[string]any)
			id, _ := art["artifactId"].(string)
			if appendFlag, _ := res["append"].(bool); !appendFlag {
				generation[id]++
			}
			key := "a:" + id + "#" + strconv.Itoa(generation[id])
			for _, f := range a2aParts(art) {
				out = append(out, streamField{key: key, textField: f})
			}
			return out
		}
		for _, f := range a2aParts(res) {
			out = append(out, streamField{key: "m", complete: true, textField: f})
		}
		return out
	}
}

// jsonRPCErrorBody is the A2A-native block: a JSON-RPC error carrying the
// request's id. Like the other blocks, it never names what matched.
func jsonRPCErrorBody(id json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": a2aBlockCode, "message": "blocked by ai_security policy"}})
	return b
}

func jsonRPCBlock(id json.RawMessage) *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ImmediateResponse{ImmediateResponse: &extproc.ImmediateResponse{
		Status: &typev3.HttpStatus{Code: typev3.StatusCode_OK},
		Headers: &extproc.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{{
			Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("application/json")}}}},
		Body:    jsonRPCErrorBody(id),
		Details: "ai_security",
	}}}
}

// cardBlock answers a blocked agent-card fetch with a plain 403.
func cardBlock() *extproc.ProcessingResponse {
	return blockResponse()
}
