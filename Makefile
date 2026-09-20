BINARY := bin/inspector
PKG    := ./...

.PHONY: all build test vet lint fmt run tidy vuln eval eval-baseline bench clean

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

tidy:
	go mod tidy

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

clean:
	rm -rf bin
