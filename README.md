# ai_security

Security layer for enterprise AI agents: an inspection, policy and evidence service that the agent
gateway (agentgateway) calls to inspect tool definitions, input prompts, tool calls, tool/RAG content and LLM
output — blocking prompt injection and redacting sensitive data. Customer-run data plane, vendor-hosted control
plane.

It is not a proxy: auth, routing, retries and provider adapters stay in the gateway.

Status: **Phase 0 (scaffold)**. The layout, the core interfaces and the service skeleton are in place; the
detectors, the policy evaluator and the gateway adapters are stubs. Every hop is allowed.

- [Design](docs/DESIGN.md)
- [Roadmap](docs/ROADMAP.md)

## Layout

| Path | What it is |
|---|---|
| `cmd/inspector` | The data-plane service: HTTP (`/healthz`, `http` adapter) on `:8080`, gRPC (agentgateway ext_proc + ExtMcp) on `:9000` |
| `internal/core` | Gateway-neutral `Inspect(ctx, Request) (Verdict, error)` and the pipeline that wires the stages |
| `internal/detect` | `Detector` interface, registry, and the v1 detector / finding-type vocabulary |
| `internal/policy` | The YAML policy of DESIGN §3.6, its loader, and the evaluator |
| `internal/session` | Cross-surface taint, tool-definition pins and blocked tools (in-memory, or Redis with `REDIS_ADDR`) |
| `internal/audit` | Metadata-and-hashes-only event and a JSON-lines sink |
| `internal/adapters/{agentgateway,http}` | Wire-format adapters for agentgateway (LLM and MCP routes; A2A in Phase 2) and plain HTTP |
| `deploy/e2e` | Phase 1 e2e stack: ai_platform's gateway stack + this inspector + a sample MCP server ([README](deploy/e2e/README.md)) |
| `test/e2e` | The e2e suite (`-tags e2e`; `make e2e-up e2e`) |

## Develop

```bash
make build test vet   # or: go build ./... && go test ./... && go vet ./...
make lint             # needs golangci-lint v2
make run              # ADDR=:8080 by default
```

Configuration is environment only: `ADDR`, `POLICY_FILE` (optional; a fail-closed default policy is used when
unset), `AUDIT_FILE` (optional; stdout when unset), `TAINT_TTL`.
