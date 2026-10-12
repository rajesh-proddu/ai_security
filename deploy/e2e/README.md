# Phase 1 e2e stack

ai_platform's local gateway stack, consumed rather than copied, with this repo's
inspection service added and the sample MCP server replaced by ours.

| Service | From | Port |
|---|---|---|
| `agentgateway` | ai_platform `deploy/local/docker-compose.yml` + `gateway/config.yaml` | 3000 (LLM `/v1/*`, MCP `/mcp`), 15020 metrics, 15021 readiness |
| `vllm` | ai_platform (CPU, `Qwen/Qwen2.5-0.5B-Instruct`) | 8000 |
| `redis` | ai_platform | 6379 |
| `mcp-everything` | **this repo**, `mcp-sample/` (via `ai-platform.override.yml`) | 3001 (internal) |
| `ai-security-inspector` | **this repo** | 8080 HTTP, 9000 gRPC (ext_proc + ExtMcp) |

`ai_platform` must be checked out next to this repo (`../ai_platform`). The
gateway config names `ai-security-inspector:9000` and `mcp-everything:3001/mcp`,
so those service names are a contract.

## Run

```bash
make e2e-up     # build images, start the stack, wait for gateway + inspector
make e2e        # go test -tags e2e ./test/e2e/
make e2e-down
```

The suite asserts on what the agent receives and on the inspector's audit
events (`docker compose logs ai-security-inspector`), never on model text.
Every test uses a fresh session id, because Redis keeps taint and blocked tools
while the stack is up. `policy.yaml` is the policy under test.

## The sample MCP server

`mcp-sample/` is its own Go module, so its dependencies stay out of the
product's `go.mod`. Each tool exists for one exit criterion:

| Tool | Exercises |
|---|---|
| `get_video_description` | a result with an indirect prompt injection: flagged, session tainted |
| `get_customer` | a card number in a tool result: redacted |
| `summarize_document` | a poisoned description: removed from `tools/list`, calls refused |
| `send_email` | the high-risk call a tainted session must not make |

## Memory

vLLM peaked at **6.4 GiB** while starting in this stack (more than the 5.4 GiB
ai_platform `study/01` measured standalone). WSL2 and Docker Desktop share a
7.48 GiB default, which is not enough: vLLM is OOM-killed while allocating its
KV cache. The full suite has run with `memory=9GB` under `[wsl2]` in
`%UserProfile%\.wslconfig` (applied with `wsl --shutdown`). The MCP tests and
the latency test do not need vLLM; the two LLM-path tests do. The first LLM
request pays about two minutes of compilation.
