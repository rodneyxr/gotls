#!/usr/bin/env bash

# Setup script to install git hooks and configure the repository

set -e

echo "🔧 Setting up gotls development environment..."

# Install git hooks
echo "📁 Installing git hooks..."
# git config core.hooksPath .githooks

# Ensure hooks are executable
chmod +x .githooks/*

# Install pre-commit if available (optional)
if command -v pre-commit >/dev/null 2>&1; then
    echo "📦 Installing pre-commit hooks..."
    pre-commit install
else
    echo "ℹ️  pre-commit not found, using custom git hooks only"
fi

# Download dependencies
echo "📦 Downloading Go dependencies..."
go mod download

# Generate initial documentation
echo "📚 Generating initial documentation..."
go generate ./...

echo "✅ Setup complete!"
echo ""
echo "Development workflow:"
echo "  - Commit messages must follow conventional commits format"
echo "  - Pre-commit hooks will run automatically"
echo "  - Documentation is auto-generated on commit"
echo "  - Releases are automated via semantic versioning"
echo ""
echo "Example commit: git commit -m 'feat(info): add certificate inspection command'"
