.PHONY: build test clean docs setup install-hooks release

# Build the binary
build:
	@COMMIT=`git rev-parse --short HEAD` || COMMIT=unknown; \
	DATE=`date -u +%Y-%m-%dT%H:%M:%SZ`; \
	VERSION=`git describe --tags --exact-match 2>/dev/null || echo dev`; \
	echo "Building gotls version: $$VERSION commit: $$COMMIT date: $$DATE"; \
	go build -ldflags "-X 'gotls/cmd.version=$$VERSION' -X 'gotls/cmd.commit=$$COMMIT' -X 'gotls/cmd.date=$$DATE'" -o gotls .

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -f gotls
	rm -rf build/
	rm -rf dist/

# Generate documentation
docs:
	go run ./tools/generate_docs

# Setup development environment
setup:
	./setup.sh

# Install git hooks manually
install-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/*

# Build for multiple platforms
build-all:
	mkdir -p build
	GOOS=linux GOARCH=amd64 go build -o build/gotls-linux-amd64 .
	GOOS=darwin GOARCH=amd64 go build -o build/gotls-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o build/gotls-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -o build/gotls-windows-amd64.exe .

# Run linting
lint:
	go vet ./...
	gofmt -s -l .

# Format code
fmt:
	gofmt -s -w .

# Run pre-commit checks manually
pre-commit:
	./.githooks/pre-commit

# Install the binary to PATH
install: build
	sudo mv gotls /usr/local/bin/

help:
	@echo "Available targets:"
	@echo "  build       - Build the gotls binary"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  docs        - Generate documentation"
	@echo "  setup       - Setup development environment"
	@echo "  install-hooks - Install git hooks"
	@echo "  build-all   - Build for multiple platforms"
	@echo "  lint        - Run linting"
	@echo "  fmt         - Format code"
	@echo "  pre-commit  - Run pre-commit checks"
	@echo "  install     - Install binary to /usr/local/bin"
