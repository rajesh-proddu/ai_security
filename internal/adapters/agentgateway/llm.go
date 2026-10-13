package agentgateway

import (
	"context"
	"errors"
	"io"
	"mime"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// LLM serves Envoy's ext_proc protocol on agentgateway's LLM routes
// (DESIGN §3.2), with both body modes set to fullDuplexStreamed.
//
// In that mode the gateway keeps no copy of the body: whatever this server
// streams back is what goes upstream (or to the client). So every path below
// sends the body back, changed or not; a reply without a body mutation would
// empty it (docs/spikes/agentgateway-extproc.md).
//
// Request bodies are buffered to end of stream, inspected, and sent back in
// one piece. Non-streaming JSON responses are handled the same way, and the
// reply to their response headers is held until the body is inspected, so a
// block can still become a clean error response. Streaming (SSE) responses go
// through a sliding window that holds back text until it is safe to release
// (stream.go).
//
// OpenAI chat completions are parsed by message, keeping roles and marking
// `tool` messages untrusted. Every other JSON body on the route (Anthropic
// messages, OpenAI responses and embeddings, Gemini, rerank) is inspected
// without parsing its format: its prose fields go to input or output, skipping
// ids, enums and base64 media (see textLeaves). Otherwise an agent could avoid
// every input rule by calling a different endpoint on the same gateway.
type LLM struct {
	extproc.UnimplementedExternalProcessorServer
	Inspector core.Inspector
}

// NewLLM returns an ext_proc server over the given inspector.
func NewLLM(in core.Inspector) *LLM { return &LLM{Inspector: in} }

// llmStream is the state of one HTTP exchange.
type llmStream struct {
	session string
	path    string

	reqBody []byte

	// inspectResponse is set when the response is a non-streaming 2xx JSON
	// body; its header reply is then held in heldHeaders until the body is in.
	inspectResponse bool
	heldHeaders     bool
	respBody        []byte

	// window is set for a 2xx streamed (SSE) response.
	window *streamWindow
}

func (l *LLM) Process(s extproc.ExternalProcessor_ProcessServer) error {
	ctx := s.Context()
	st := &llmStream{}
	for {
		msg, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		replies, done, err := l.handle(ctx, st, msg)
		if err != nil {
			return err
		}
		for _, r := range replies {
			if err := s.Send(r); err != nil {
				return err
			}
		}
		if done {
			return nil
		}
	}
}

// handle returns the replies for one message, and whether the exchange is over
// (an immediate response ends it).
func (l *LLM) handle(ctx context.Context, st *llmStream, msg *extproc.ProcessingRequest) ([]*extproc.ProcessingResponse, bool, error) {
	switch r := msg.GetRequest().(type) {
	case *extproc.ProcessingRequest_RequestHeaders:
		h := headerMap(r.RequestHeaders.GetHeaders())
		st.path = h[":path"]
		st.session = sessionFrom(func(k string) string { return h[k] })
		return one(requestHeadersReply()), false, nil

	case *extproc.ProcessingRequest_RequestBody:
		st.reqBody = append(st.reqBody, r.RequestBody.GetBody()...)
		if !r.RequestBody.GetEndOfStream() {
			return nil, false, nil
		}
		body, blocked, err := l.inspectRequest(ctx, st)
		if err != nil {
			return nil, false, err
		}
		if blocked {
			return one(blockResponse()), true, nil
		}
		return one(requestBodyReply(body)), false, nil

	case *extproc.ProcessingRequest_ResponseHeaders:
		h := headerMap(r.ResponseHeaders.GetHeaders())
		hasBody := !r.ResponseHeaders.GetEndOfStream() && success(h[":status"])
		if hasBody && isSSE(h["content-type"]) {
			st.window = newStreamWindow(func(ctx context.Context, text string) (core.Verdict, error) {
				return l.Inspector.Inspect(ctx, core.Request{
					Surface: core.SurfaceOutput,
					Session: st.session,
					Parts:   []core.Part{{Role: "assistant", Text: text, Trust: core.TrustTrusted}},
				})
			})
			return one(responseHeadersReply()), false, nil
		}
		st.inspectResponse = hasBody && isJSON(h["content-type"])
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
		body, blocked, err := l.inspectResponse(ctx, st)
		if err != nil {
			return nil, false, err
		}
		if blocked {
			return one(blockResponse()), true, nil
		}
		var out []*extproc.ProcessingResponse
		if st.heldHeaders {
			out = append(out, responseHeadersReply())
			st.heldHeaders = false
		}
		return append(out, responseBodyReply(body, true)), false, nil

	case *extproc.ProcessingRequest_RequestTrailers:
		return one(&extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_RequestTrailers{RequestTrailers: &extproc.TrailersResponse{}}}), false, nil

	case *extproc.ProcessingRequest_ResponseTrailers:
		return one(&extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ResponseTrailers{ResponseTrailers: &extproc.TrailersResponse{}}}), false, nil
	}
	return nil, false, nil
}

// inspectRequest inspects a chat completions request: the conversation on the
// input surface, and any `tool` messages — tool results the agent passes back —
// on the tool_result surface (DESIGN §3.4). Any other JSON body is inspected as
// input without parsing its format.
func (l *LLM) inspectRequest(ctx context.Context, st *llmStream) ([]byte, bool, error) {
	v, err := decodeJSON(st.reqBody)
	if err != nil {
		// Not ours to reject: the gateway answers malformed bodies itself.
		return st.reqBody, false, nil
	}
	if !isChat(st.path) {
		return l.inspectAny(ctx, st, core.SurfaceInput, v, st.reqBody)
	}
	chat, _ := v.(map[string]any)
	messages, _ := chat["messages"].([]any)

	var input, results []textField
	var inputRoles, resultRoles []string
	for _, m := range messages {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		role, _ := msg["role"].(string)
		for _, f := range messageText(msg) {
			if role == "tool" {
				results, resultRoles = append(results, f), append(resultRoles, role)
			} else {
				input, inputRoles = append(input, f), append(inputRoles, role)
			}
		}
	}
	model, _ := chat["model"].(string)

	changed := false
	for _, batch := range []struct {
		surface core.Surface
		fields  []textField
		roles   []string
		trust   core.Trust
	}{
		{core.SurfaceInput, input, inputRoles, core.TrustTrusted},
		{core.SurfaceToolResult, results, resultRoles, core.TrustUntrusted},
	} {
		if len(batch.fields) == 0 {
			continue
		}
		req := core.Request{Surface: batch.surface, Session: st.session, Source: model, Parts: make([]core.Part, len(batch.fields))}
		for i, f := range batch.fields {
			req.Parts[i] = core.Part{Role: batch.roles[i], Text: f.text, Trust: batch.trust}
		}
		verdict, err := l.Inspector.Inspect(ctx, req)
		if err != nil {
			return nil, false, err
		}
		switch verdict.Action {
		case core.ActionBlock:
			return nil, true, nil
		case core.ActionRedact:
			if redactFields(batch.fields, verdict.Redactions) {
				changed = true
			}
		}
	}
	if !changed {
		return st.reqBody, false, nil
	}
	b, err := encodeJSON(chat)
	return b, false, err
}

// inspectResponse inspects the assistant text of a chat completions response
// on the output surface, and any other JSON response without parsing its
// format.
func (l *LLM) inspectResponse(ctx context.Context, st *llmStream) ([]byte, bool, error) {
	v, err := decodeJSON(st.respBody)
	if err != nil {
		return st.respBody, false, nil
	}
	if !isChat(st.path) {
		return l.inspectAny(ctx, st, core.SurfaceOutput, v, st.respBody)
	}
	resp, _ := v.(map[string]any)
	choices, _ := resp["choices"].([]any)
	var fields []textField
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		if msg, ok := choice["message"].(map[string]any); ok {
			fields = append(fields, messageText(msg)...)
		}
	}
	if len(fields) == 0 {
		return st.respBody, false, nil
	}
	model, _ := resp["model"].(string)
	verdict, err := l.Inspector.Inspect(ctx, core.Request{
		Surface: core.SurfaceOutput,
		Session: st.session,
		Source:  model,
		Parts:   parts(fields, "assistant", core.TrustTrusted),
	})
	if err != nil {
		return nil, false, err
	}
	switch verdict.Action {
	case core.ActionBlock:
		return nil, true, nil
	case core.ActionRedact:
		if redactFields(fields, verdict.Redactions) {
			b, err := encodeJSON(resp)
			return b, false, err
		}
	}
	return st.respBody, false, nil
}

// inspectAny inspects a JSON body of a format we do not parse: its prose
// fields, one part each, with the model as the source when the body names one.
// raw is returned unchanged unless a redaction applies.
func (l *LLM) inspectAny(ctx context.Context, st *llmStream, surface core.Surface, v any, raw []byte) ([]byte, bool, error) {
	var fields []textField
	textLeaves(v, &fields)
	if len(fields) == 0 {
		return raw, false, nil
	}
	model := ""
	if m, ok := v.(map[string]any); ok {
		model, _ = m["model"].(string)
	}
	verdict, err := l.Inspector.Inspect(ctx, core.Request{
		Surface: surface,
		Session: st.session,
		Source:  model,
		Parts:   parts(fields, "", core.TrustTrusted),
	})
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
	return raw, false, nil
}

// messageText returns a chat message's text: `content` as a string, or the
// `text` of each text part when content is an array of parts.
func messageText(msg map[string]any) []textField {
	if f, ok := stringField(msg, "content"); ok {
		return []textField{f}
	}
	items, _ := msg["content"].([]any)
	var out []textField
	for _, it := range items {
		part, ok := it.(map[string]any)
		if !ok || part["type"] != "text" {
			continue
		}
		if f, ok := stringField(part, "text"); ok {
			out = append(out, f)
		}
	}
	return out
}

// isChat reports whether the path is an OpenAI chat completions call, the
// first format DESIGN §3.2 parses.
func isChat(path string) bool {
	p, _, _ := strings.Cut(path, "?")
	return strings.HasSuffix(p, "/chat/completions")
}

func isSSE(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "text/event-stream"
}

func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/json"
}

func success(status string) bool {
	n, err := strconv.Atoi(status)
	return err == nil && n >= 200 && n < 300
}

// headerMap flattens ext_proc headers. agentgateway sends most values as
// raw_value bytes and pseudo-headers as value; both are read.
func headerMap(hm *corev3.HeaderMap) map[string]string {
	out := map[string]string{}
	for _, h := range hm.GetHeaders() {
		v := h.GetValue()
		if len(h.GetRawValue()) > 0 {
			v = string(h.GetRawValue())
		}
		out[strings.ToLower(h.GetKey())] = v
	}
	return out
}

func one(r *extproc.ProcessingResponse) []*extproc.ProcessingResponse {
	return []*extproc.ProcessingResponse{r}
}

func requestHeadersReply() *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_RequestHeaders{RequestHeaders: &extproc.HeadersResponse{}}}
}

func responseHeadersReply() *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extproc.HeadersResponse{}}}
}

func streamed(body []byte, eos bool) *extproc.CommonResponse {
	return &extproc.CommonResponse{BodyMutation: &extproc.BodyMutation{Mutation: &extproc.BodyMutation_StreamedResponse{
		StreamedResponse: &extproc.StreamedBodyResponse{Body: body, EndOfStream: eos}}}}
}

func requestBodyReply(body []byte) *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_RequestBody{RequestBody: &extproc.BodyResponse{Response: streamed(body, true)}}}
}

func responseBodyReply(body []byte, eos bool) *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ResponseBody{ResponseBody: &extproc.BodyResponse{Response: streamed(body, eos)}}}
}

// blockBody follows the OpenAI error shape, so agent SDKs surface it as an API
// error. Like the MCP reason, it never names what matched.
const blockBody = `{"error":{"message":"blocked by ai_security policy","type":"ai_security_block","code":"content_blocked"}}`

func blockResponse() *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ImmediateResponse{ImmediateResponse: &extproc.ImmediateResponse{
		Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
		Headers: &extproc.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{{
			Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("application/json")}}}},
		Body:    []byte(blockBody),
		Details: "ai_security",
	}}}
}
