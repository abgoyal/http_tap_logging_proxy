BINARY := http-tap-proxy
LDFLAGS := -ldflags "-s -w"

.PHONY: build build-linux build-windows test test-short bench lint clean

# Default build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) .

# Cross-compilation (CGO-free)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux .

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY).exe .

# Run all tests
test:
	go test -v -timeout 120s

# Quick tests (skip stress tests)
test-short:
	go test -v -short -timeout 60s

# Run benchmarks
bench:
	go test -bench=. -benchtime=2s -timeout 120s

# Lint and format
lint:
	go fmt ./...
	go vet ./...
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed, skipping"

# Clean build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-linux $(BINARY).exe
	rm -rf test_output/
