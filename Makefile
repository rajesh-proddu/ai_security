BINARY := bin/inspector
PKG    := ./...

.PHONY: all build test vet lint fmt run tidy vuln eval eval-baseline bench clean e2e-up e2e e2e-down

all: build test vet

build:
	go build -o $(BINARY) ./cmd/inspector

test:
	go test $(PKG)

vet:
	go vet $(PKG)

# Requires golangci-lint (see .github/workflows/ci.yml for the pinned version).
lint:
	golangci-lint run $(PKG)

fmt:
	gofmt -l -w .

run: build
	./$(BINARY)

eval:
	go run ./cmd/eval -check evals/baseline.json

eval-baseline:
	go run ./cmd/eval -write-baseline evals/baseline.json

# Fast-path latency against the DESIGN §2 budget (p99 <= 20 ms).
bench:
	go test ./internal/core/ -run '^$$' -bench BenchmarkFastPath -benchtime 200x -v

# Phase 1 e2e stack (deploy/e2e): ai_platform's gateway stack plus this repo's
# inspector and sample MCP server. Needs Docker and ai_platform checked out
# next to this repo.
E2E := docker compose -f deploy/e2e/docker-compose.yml

e2e-up:
	docker build -q -t ai-security/mcp-sample:e2e deploy/e2e/mcp-sample
	$(E2E) up -d --build
	@echo "waiting for the gateway and the inspector"
	@for i in $$(seq 1 60); do curl -sf localhost:15021/healthz/ready >/dev/null && curl -sf localhost:8080/healthz >/dev/null && exit 0; sleep 2; done; echo "stack not ready"; exit 1

# vLLM on CPU takes minutes to become healthy; the LLM tests wait on it.
e2e:
	go test -tags e2e -count=1 -v ./test/e2e/

e2e-down:
	$(E2E) down

tidy:
	go mod tidy

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

clean:
	rm -rf bin
