BINARY := bin/inspector
PKG    := ./...

.PHONY: all build test vet lint fmt run tidy vuln clean

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

tidy:
	go mod tidy

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

clean:
	rm -rf bin
