# e2e stack — skeleton

**This is a skeleton, not a working stack.** It exists so Phase 1 has a place to
put the e2e environment; most of it is deliberately unfilled.

What the full stack will be (ROADMAP Phase 1): an agent gateway, a local
OpenAI-compatible model server, a sample MCP server, and this repo's inspection
service behind the gateway's ext_proc hook.

## What works today

```bash
docker compose up inspector
curl localhost:8080/healthz
curl -s localhost:8080/v1/inspect \
  -H 'content-type: application/json' \
  -d '{"surface":"input","session":"s1","parts":[{"role":"user","text":"hello"}]}'
```

The Phase 0 service allows everything: the detectors and the policy evaluator
are stubs (see `internal/detect` and `internal/policy`).

## What is not filled in, and why

- **The gateway configuration is not ours.** DESIGN §7 and ROADMAP
  "Cross-repo dependencies": the agentgateway config (LLM + MCP routes) is owned
  by [`ai_platform`](https://github.com/rajesh-proddu/ai_platform) and is not
  committed there yet. Phase 1 may carry a temporary local config in
  `deploy/e2e/gateway/`, to be deleted once `ai_platform` P0 ships.
- **Images are unpinned.** Every `image: ""` with a `TODO(phase-1)` is a value
  this repo has not verified. Guessing at an image tag or a config schema here
  would be worse than leaving it empty.
- The unverified services sit behind the `gateway` compose profile, so
  `docker compose up` does not try to start them.

Start them once they are filled in with:

```bash
docker compose --profile gateway up
```
