# GoTLS

Lightweight tooling to create a local Certificate Authority (CA) and issue TLS certificates for local development.

GoTLS focuses on simplicity: generate a CA, create server certificates (including wildcard handling), and inspect certificates. It also supports generating fullchain files (certificate + CA) and includes doc generation and CI/release automation for maintainers.

## Features
- Create a self-signed CA and sign server certificates
- Wildcard certificate support
- Inspect certificates and keys with `gotls info`
- Generate fullchain PEM files and output base64-encoded chains

## Quickstart

1. Clone and build:

```sh
git clone https://github.com/rodneyxr/gotls
cd gotls
go build -o gotls .
```

2. Create a CA and certificates for services:

```sh
# Generate a CA and certificates for example.dev and api.example.dev
./gotls -n 'GoTLS CA' -s example.dev -s api.example.dev -d ./certs
```

3. Inspect a certificate:

```sh
./gotls info ./certs/example.dev.crt
```

# Development

Dependencies are managed with Go modules.

Install deps and build:

```sh
go mod tidy
go build ./...
```

## Generate documentation (markdown & man pages):

```sh
make docs
# or
go run ./tools/generate_docs
```

## Tests & formatting

```sh
# run tests
make test

# format code
make fmt
```

## Git hooks

A pre-commit hook is provided to run formatting, vet, tests and doc generation. Install hooks with:

```sh
make install-hooks
```

## Contributing

Contributions are welcome. Please follow these guidelines:
- Use conventional commits (feat, fix, docs, chore, etc.) — CI uses these to determine release bumps
- Write tests for new functionality
- Run `make fmt`, `make test` and `make docs` before opening a PR

When opening a PR, include a clear description and link to any relevant issues.

## Releases & CI

This project includes GitHub Actions and GoReleaser configuration to produce releases automatically:
- On push to `main` the pipeline runs tests and (if commit messages follow conventional commits) a semantic version release is created
- Binaries are built for multiple platforms using GoReleaser
