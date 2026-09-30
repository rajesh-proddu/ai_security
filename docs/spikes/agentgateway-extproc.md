# Spike: agentgateway ext_proc and MCP hooks (ROADMAP Phase 1)

Run 2026-09-29 against **agentgateway v1.5.0** (release binary, sha256-verified, git `fe67324`), using
`ai_platform` branch `p0-scaffold` `gateway/config.yaml` with only the hostnames changed to localhost.
Upstreams: a fake OpenAI-compatible server that logs what it receives and echoes the prompt, and
`@modelcontextprotocol/server-everything` over streamable HTTP. The inspector was stood in for by a throwaway gRPC
server that logged every message and replied according to a mode flag. Captures from those runs are in
`internal/adapters/agentgateway/testdata/`, one JSON object per gRPC message (`svc`, `stream`, `dir` in/out, `msg` as
protojson):

| File | Contents |
|---|---|
| `extproc_llm_echo.jsonl` | LLM: one non-streaming and one streaming chat, every body chunk echoed back |
| `extproc_llm_stream_stop.jsonl` | LLM: streaming chat, ended by the server at the second response chunk |
| `extmcp_session_redact.jsonl` | MCP via ExtMcp: `initialize`, `tools/list`, `tools/call` with the params redacted; includes `metadata_context` |
| `extmcp_tools_list_drop.jsonl` | MCP via ExtMcp: `echo` removed from `tools/list`. **Two sessions**, because the script ran twice |

Evidence below is either **observed** (a request was sent and the result recorded) or **source** (read in the
agentgateway source at `fe67324`; not exercised).

## Answers to the four spike questions

### 1. What arrives on LLM routes and on MCP routes

**LLM route (`llm.policies.extProc`): standard Envoy `envoy.service.ext_proc.v3`.** Observed:

- The first message is `request_headers` with a `protocol_config` giving both body modes as `FULL_DUPLEX_STREAMED`. Pseudo-headers
  (`:path`, `:method`, `:authority`) and all client headers are included, `x-session-id` among them. There is no
  `metadata_context` and no `attributes`, so **the session ID has to come from the header**.
- The request body is the **caller-facing** OpenAI payload (`"model":"chat-default"`), before alias resolution. That is
  the side DESIGN §3.2 says we inspect.
- The response body is also sent to ext_proc, **including error bodies the gateway generates itself** (e.g. its own 400).
- Streaming responses arrive as one `response_body` message per upstream write, with a final empty
  `end_of_stream: true`. Against the fake backend that happened to be one SSE event per chunk. **That's a
  property of the backend, not a guarantee.** The adapter must treat the body as a byte stream and re-frame SSE
  itself (DESIGN §3.5 windowing).

**MCP route: two options, and the one `ai_platform` configured is the worse fit.**

- **`mcp.policies.extProc` (what `ai_platform` has now).** Observed: ext_proc sees the raw streamable-HTTP exchange.
  - The request is a JSON-RPC envelope (`{"method":"tools/call","params":{"name":"echo","arguments":{...}}}`), so the tool
    name and arguments are in the body, not in metadata.
  - The response is **SSE-framed** (`event: message\ndata: {...}`), and it **doesn't carry the method**.
  - `notifications/*` and `initialize` pass through the same hook.
  - The adapter would have to parse JSON-RPC and SSE and match each response to its request.
- **`mcp.policies.mcpGuardrails` with a `remote` processor: agentgateway's own `agentgateway.dev.ext_mcp.ExtMcp`
  gRPC service.** This service is not mentioned in DESIGN. It has been in agentgateway since v1.3.0 and its proto is unchanged since. Observed:
  - `CheckRequest(McpRequest)` gives:
    - `method`;
    - `params` as raw JSON (the tool name and arguments, without the envelope);
    - `service_names`, the backend in its native namespace;
    - all request headers, including `x-session-id` and the gateway-minted `mcp-session-id`.
  - `CheckResponse(McpResponse)` gives the JSON-RPC `result` as plain JSON, not SSE.
  - Notifications do not trigger the hook.
  - `McpResponse` **has no headers**, but both phases carry `metadata_context`, which is filled from CEL in the
    processor config. `metadata: {session: 'request.headers["x-session-id"]'}` delivered `session: "s1"` on
    the response hook too, so tool results can be tied to the session.
  - Source: tool names are unmuxed for single-target methods such as `tools/call`. For fan-out methods such as `*/list`
    they follow the client-facing view, which is muxed only when there's more than one target.

### 2. Block and redact

| Action | LLM (ext_proc, full duplex) | MCP (ExtMcp) |
|---|---|---|
| Redact request | ✅ Observed. Return `StreamedBodyResponse` with the rewritten bytes. A change in length is fine: the gateway drops `content-length` and upstream parsed the result. | ✅ Observed. `McpRequestResult.mutated` = new `params` JSON; upstream received the rewritten arguments. |
| Redact response | ✅ Observed, including on a streamed response, chunk by chunk | ✅ Observed. `McpResponseResult.mutated` = new `result` JSON. |
| Block request | ✅ Observed. `ImmediateResponse` gave the client our status, headers and body exactly (403 + JSON), and **upstream was never called**. | ✅ Observed. `AuthorizationError{PERMISSION_DENIED, reason}` gave JSON-RPC error `-32001` with our reason. |
| Block mid-stream | ⚠️ Observed. `ImmediateResponse` after the headers are sent **silently truncates** the stream: the client sees HTTP 200 and a clean close, with no error. What works instead: reply with `StreamedBodyResponse{body: <SSE error event + "data: [DONE]">, end_of_stream: true}`. The client gets an explicit error and its stream ends. ⚠️ **But upstream isn't cancelled.** ext_proc kept receiving every remaining upstream chunk (all 8 in `extproc_llm_stream_stop.jsonl`), and each one still needs a reply (empty body, `end_of_stream: true`), so the tokens are still generated and paid for. | n/a (the result is not streamed) |
| Remove a poisoned tool from `tools/list` | n/a | ✅ Observed. A mutated list without the tool reached the client. ⚠️ **But a `tools/call` to the removed tool still succeeded**: the gateway doesn't enforce the list it served. The inspector has to remember what it removed in each session and block the call as well. |

**Full-duplex contract, which the adapter must follow.** Observed and source-confirmed: in `FULL_DUPLEX_STREAMED` the gateway does
**not** keep the original body. The server has to send every chunk back as a `StreamedBodyResponse`. A
`BodyResponse` with no mutation (the usual "continue" reply) gives an **empty body**. On the LLM route that meant a 400
"LLM request body must be valid JSON" and an empty response to the client. There's no "continue" reply for body chunks in
this mode.

### 3. `failureMode`

Observed with `failClosed` and the inspector down:

- **LLM:** HTTP 500 `text/plain` `ext_proc failed: no more response messages`, and upstream isn't called.
- **MCP (ExtMcp):** HTTP 200 carrying JSON-RPC error `-32603` `mcpGuardrails checkRequest failed: … Connection refused`.
  Even `initialize` fails, so no MCP session can be set up.

**`failOpen` doesn't work on LLM routes in this mode.** Observed with the LLM `extProc` set to `failOpen` and the inspector down:
chat POSTs, streaming or not, still got the same 500 and never reached upstream. Only a body-less `GET /v1/models` got through.
Source: the gateway fails open only if the body **has not started** streaming to the processor
(`should_fail_open_on_disconnect`). In `FULL_DUPLEX_STREAMED` the request body is marked as started before any reply
is awaited, so any request with a body fails closed whatever the setting. ExtMcp `failOpen` (source) passes the call.
Both default to `failClosed`, which matches the policy's `on_error: fail_closed` default, so the fail-closed contract holds.

### 4. Does agentgateway pin tool definitions?

**No.** There's no pinning, hashing or rug-pull detection anywhere in the v1.5.0 source (source). v1 keeps its
own pinning (`internal/core/pipeline.go` `checkPin`). With ExtMcp, pins are recorded from the `tools/list` result and checked on
`tools/call`. `tools/call` doesn't carry the tool definition, so the adapter keys pins by session + service name + tool name.

## Decision (accepted 2026-09-30, DESIGN v0.4)

**LLM routes use ext_proc as configured. MCP routes use `mcpGuardrails` (ExtMcp), not ext_proc.** Session identity:
`x-session-id` first on both paths (DESIGN §6 decision 2).

- ExtMcp hands over exactly what the pipeline needs (method, tool name, arguments, result JSON, backend, session) with no
  SSE parsing, no request/response matching and no notification noise, and its pass / mutate / reject replies match
  `core.Verdict` directly.
- Cost: ExtMcp is an agentgateway protocol, not an Envoy standard. That affects only this adapter; the LiteLLM path has no MCP hook either way (DESIGN §3.2).
- Follow-up: DESIGN §3.2 is updated. Still to do: change `ai_platform`'s `mcp.policies` to:

```yaml
mcpGuardrails:
  processors:
    - kind: remote
      methods: { "*": full }        # gateway warns resources/(un)subscribe are response-only; harmless
      host: ai-security-inspector:9000
      failureMode: failClosed
      metadata:
        session: 'request.headers["x-session-id"]'
```

Both gRPC services can be served on the one `:9000` listener, as the spike server did, so the port contract doesn't change.

## Cross-repo issues found

1. **`ai_platform/gateway/config.yaml` does not load under v1.5.0.** agentgateway expands `$NAME` references in
   the raw file, **comments included**. The comment "`` `$VAR` expansion is only confirmed for `apiKey` ``" fails
   startup with `error looking key 'VAR' up: environment variable not found`. The fix is to reword that comment.
   This means the P0 stack has not yet started with this config.
2. **Inspector env and Dockerfile drift.** `ai_platform`'s commented-out inspector service sets
   `INSPECTOR_EXTPROC_ADDR`, `INSPECTOR_HTTP_ADDR` and `INSPECTOR_REDIS_URL`, and builds `build/Dockerfile`. This repo reads
   `ADDR` and `REDIS_ADDR` and has `Dockerfile` at the root. One side has to change before the e2e stack works.
3. **`ai_platform`'s "flip both failureModes to failOpen for gateway-only work" does not work for the LLM route.** See §3:
   with `fullDuplexStreamed`, `failOpen` still rejects every request that has a body. For gateway-only work, remove the LLM
   `extProc` policy rather than setting it to `failOpen`.
4. `@modelcontextprotocol/server-everything` needs Node ≥ 20. On Node 18 it only runs with
   `NODE_OPTIONS=--experimental-global-webcrypto`. Not an issue in the `node:22-alpine` compose service.

## Implications for the adapter (next step)

- `Processor` serves both `envoy.service.ext_proc.v3.ExternalProcessor` and `agentgateway.dev.ext_mcp.ExtMcp`
  on `:9000`. This adds the `go-control-plane` and `grpc` dependencies. The ExtMcp Go types are generated by agentgateway at
  `api/ext_mcp.pb.go`; that module requires Go 1.27, so vendor the generated files or generate them from the proto.
- LLM, per stream: read the session from `x-session-id` in `request_headers`; buffer the request body to
  `end_of_stream` → `input` surface; send back the original or redacted body as one `StreamedBodyResponse`, or send
  `ImmediateResponse` to block. Response: window over chunks → `output` surface; always send the bytes back; for a
  mid-stream block, end with an SSE error event and `end_of_stream: true`, then keep answering the remaining upstream chunks
  with empty bodies until the stream closes.
- MCP: `tools/list` result → `tool_definition` surface plus pin; `tools/call` params → `tool_call` surface (taint check
  and pin check, including tools removed from the list earlier in the session); `tools/call` result → `tool_result`
  surface (redact and taint). Session from `metadata_context.session`.
- The spike did not measure fast-path latency through the gateway; that is part of the Phase 1 e2e work.
