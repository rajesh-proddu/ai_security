# ai_security — Roadmap

Architecture and rationale: [DESIGN.md](DESIGN.md). Each phase ends in something demoable and tested.

**v1 as scoped in DESIGN §2 = Phases 0–2**: the inspection service, all five surfaces, and agentgateway integration
across LLM, MCP and A2A traffic. ai_security does not build a proxy; the gateway comes from `ai_platform`
(DESIGN §6 decision 7: agentgateway only).

| Phase | Theme | Deliverable | Exit criteria |
|---|---|---|---|
| **0** | Scaffold | Go module, layout (`cmd/inspector`, `internal/core`, `internal/detect`, `internal/policy`, `internal/adapters/{agentgateway,http}`), Makefile, CI (lint, test, `govulncheck`), Dockerfile; e2e compose skeleton — inspection service real, gateway / vLLM / sample MCP server profile-gated placeholders (their config is an `ai_platform` P0 dependency) | CI green; service serves `/healthz`; `docker compose up` starts the inspection service |
| **1** | Core + agentgateway | **Spike (done, [spikes/agentgateway-extproc.md](spikes/agentgateway-extproc.md)):** payloads, block/redact, `failureMode`, tool pinning. Then: core pipeline; `normalize`, `pii`, `secrets`, `custom_dict`, `injection_heuristic`, `exfil_url`; local YAML policy; agentgateway adapter (ext_proc for LLM routes, `ExtMcp` for MCP routes, one `:9000` listener); Redis session store with taint and tool pins; full e2e stack up (gateway + vLLM + MCP sample); local audit sink; eval harness (recommendations `evals/` pattern, `synthetic` seed set) | E2E through agentgateway: injected video description flagged and session tainted; PII in a tool result redacted; poisoned tool description blocked; a tainted session's risky MCP call blocked. Fast path p99 ≤ 20 ms. Detector precision/recall gated on `evals/baseline.json` |
| **2** | ML, streaming, tool calls, A2A | Python ML detector (CPU, ONNX; starting model `protectai/deberta-v3-base-prompt-injection-v2`, Apache-2.0); sync / flag-only placement per route; streaming window redaction via ext_proc (**done**); inspect tool calls the model emits on the LLM path, non-streaming and streamed (**done**); A2A routes via ext_proc (spike and adapter **done**; e2e pending a sample agent in `ai_platform`'s stack): agent card → `tool_definition`, `message/send` → `tool_call`, remote replies → `tool_result`; spotlighting. *Deferred:* the SDK marker for untrusted spans (needs the reco agent changed) | PII redacted mid-stream on agentgateway (**met**). A model-emitted call to a risky tool in a tainted session blocked on the LLM path (**met** through agentgateway; the vLLM e2e needs `--tool-call-parser` in `ai_platform`'s compose). A poisoned agent-card skill blocked, and an injected A2A reply taints the session so its next risky call is blocked (**met** through agentgateway against a sample A2A agent; not yet in the e2e suite). ML path p99 ≤ 100 ms. Injection eval on public benchmark sets reported per release |
| **3** | Hybrid control plane | Control-plane API + minimal UI; enrolment with mTLS; signed policy bundles (pull); metadata-only verdict ingestion; dashboard; SIEM/webhook export; Helm chart | A fresh cluster enrolls, pulls a policy, and its verdicts show on the dashboard with no body content leaving the cluster |
| **4** | Identity + RBAC | Policy on end-user and agent identity from gateway JWT/OIDC claims; per-tool and per-data-source rules (OPA/Rego), layered on the gateway's own CEL rules rather than duplicating them; RAG document-level filtering by requester; human-approval hook for high-risk tools | "Only finance agents may call `erp.*`, and only for users in group X" enforced end to end |
| **5** | Advanced detection + observability | NER-based PII; fine-tuned injection model from opt-in labelled data; per-agent behavioural anomaly detection; multi-step transaction reconstruction from `trace_id`; intent-vs-action checks | Anomaly and trace views in dashboard; detection quality tracked against the eval corpus |
| **6** | Enterprise hardening | HA / horizontal scaling, console SSO + admin RBAC, multi-region control plane, retention controls, SOC 2 prep, air-gapped mode with offline bundles, standalone proxy mode *only if* customers without a gateway ask for it | Load test at target throughput; pen test; compliance evidence collection |

## Cross-repo dependencies

| Needed by | What | Owner |
|---|---|---|
| Phase 1 e2e | agentgateway config (LLM + MCP routes) | **Landed** — `ai_platform` branch `p0-scaffold`: `gateway/config.yaml` + `deploy/local/docker-compose.yml`. The ai_security compose skeleton should consume it instead of keeping a copy. Spike changes **landed** (`ai_platform` `fd11f33`): MCP on `mcpGuardrails`, `$VAR` comment, inspector env names. **Still needed** (adapter): a second `mcpGuardrails` metadata key, `mcp_session: 'request.headers["mcp-session-id"]'`, so agents that send no `x-session-id` keep one session across MCP calls and results; and the compose comment should name `GRPC_ADDR` (default `:9000`). |
| Phase 1 | **Listener ports (contract defined by `ai_platform/gateway/README.md`)**: inspector **`:9000` gRPC (ext_proc + `ExtMcp`)**, **`:8080` webhook**. Gateway `:3000`, vLLM `:8000`, Redis `:6379`, sample MCP `:3001`. | ai_security must match |
| Phase 1 | Gateway sets `failureMode: failClosed` on both hooks, so the gateway rejects LLM and MCP traffic when the inspector is down (observed in the spike). Policy default `on_error: fail_closed` already matches (DESIGN §3.6); keep them in lockstep. | both repos |
| Phase 1 e2e | Reco agent calls LLMs through the gateway and sends `x-session-id` | `videostreamingplatform-recommendations` (`ai_platform` HLD open decision 4) |
| Phase 2 | Reco agent marks retrieved content as untrusted (SDK marker or separate message parts) | `videostreamingplatform-recommendations` |

## Open decisions

DESIGN §6: product name (#6). All other decisions are closed.
