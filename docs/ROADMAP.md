# ai_security — Roadmap

Architecture and rationale: [DESIGN.md](DESIGN.md). Each phase ends in something demoable and tested.

**v1 as scoped in DESIGN §2 = Phases 0–2**: the inspection service, all four surfaces, agentgateway integration,
and a proven swap to LiteLLM. ai_security does not build a proxy; the gateway comes from `ai_platform`.

| Phase | Theme | Deliverable | Exit criteria |
|---|---|---|---|
| **0** | Scaffold | Go module, layout (`cmd/inspector`, `internal/core`, `internal/detect`, `internal/policy`, `internal/adapters/{agentgateway,litellm,http}`), Makefile, CI (lint, test, `govulncheck`), Dockerfile; e2e compose skeleton — inspection service real, gateway / vLLM / sample MCP server profile-gated placeholders (their config is an `ai_platform` P0 dependency) | CI green; service serves `/healthz`; `docker compose up` starts the inspection service |
| **1** | Core + agentgateway | **Spike first:** confirm agentgateway ext_proc payloads for LLM and MCP routes, body mutation / immediate response, `failureMode`, and whether it already pins tool definitions. Then: core pipeline; `normalize`, `pii`, `secrets`, `custom_dict`, `injection_heuristic`, `exfil_url`; local YAML policy; agentgateway ext_proc adapter; Redis session store with taint and tool pins; full e2e stack up (gateway + vLLM + MCP sample); local audit sink; eval harness (recommendations `evals/` pattern, `synthetic` seed set) | E2E through agentgateway: injected video description flagged and session tainted; PII in a tool result redacted; poisoned tool description blocked; a tainted session's risky MCP call blocked. Fast path p99 ≤ 20 ms. Detector precision/recall gated on `evals/baseline.json` |
| **2** | ML, streaming, LiteLLM swap | Python ML detector (CPU, ONNX) with licence-checked model; sync / flag-only placement per route; streaming window redaction via ext_proc; spotlighting; `http` adapter + SDK marker for untrusted spans; LiteLLM Generic Guardrail adapter (`pre_call` / `during_call` / `post_call`) | Same e2e suite passes with agentgateway replaced by LiteLLM, only gateway config changed (MCP cases skipped and listed). PII redacted mid-stream on agentgateway. ML path p99 ≤ 100 ms. Injection eval on public benchmark sets reported per release |
| **3** | Hybrid control plane | Control-plane API + minimal UI; enrolment with mTLS; signed policy bundles (pull); metadata-only verdict ingestion; dashboard; SIEM/webhook export; Helm chart | A fresh cluster enrolls, pulls a policy, and its verdicts show on the dashboard with no body content leaving the cluster |
| **4** | Identity + RBAC | Policy on end-user and agent identity from gateway JWT/OIDC claims; per-tool and per-data-source rules (OPA/Rego), layered on the gateway's own CEL rules rather than duplicating them; RAG document-level filtering by requester; human-approval hook for high-risk tools | "Only finance agents may call `erp.*`, and only for users in group X" enforced end to end |
| **5** | Advanced detection + observability | NER-based PII; fine-tuned injection model from opt-in labelled data; per-agent behavioural anomaly detection; multi-step transaction reconstruction from `trace_id`; intent-vs-action checks | Anomaly and trace views in dashboard; detection quality tracked against the eval corpus |
| **6** | Enterprise hardening | HA / horizontal scaling, console SSO + admin RBAC, multi-region control plane, retention controls, SOC 2 prep, air-gapped mode with offline bundles, standalone proxy mode *only if* customers without a gateway ask for it | Load test at target throughput; pen test; compliance evidence collection |

## Cross-repo dependencies

| Needed by | What | Owner |
|---|---|---|
| Phase 1 e2e | agentgateway config (LLM + MCP routes) | `ai_platform` P0 — temporary local config in ai_security until it lands |
| Phase 1 e2e | Reco agent calls LLMs through the gateway and sends `x-session-id` | `videostreamingplatform-recommendations` (`ai_platform` HLD open decision 4) |
| Phase 2 | Reco agent marks retrieved content as untrusted (SDK marker or separate message parts) | `videostreamingplatform-recommendations` |
| Phase 2 | LiteLLM config equivalent to the agentgateway one | `ai_platform` |

## Open decisions

DESIGN §6: product name (#6). All other decisions are closed.
