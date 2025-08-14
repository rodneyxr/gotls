package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rodneyxr/gotls/cmd"
	"github.com/spf13/cobra/doc"
)

func main() {
	// Find the repository root by looking for go.mod
	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Printf("Failed to find repository root: %v\n", err)
		os.Exit(1)
	}

	docsDir := filepath.Join(repoRoot, "docs")
	manDir := filepath.Join(docsDir, "man")

	// Create docs directory if it doesn't exist
	if err := os.MkdirAll(docsDir, 0755); err != nil {
		fmt.Printf("Failed to create docs directory: %v\n", err)
		os.Exit(1)
	}

	// Generate markdown documentation
	rootCmd := cmd.GetRootCmd()
	if err := doc.GenMarkdownTree(rootCmd, docsDir); err != nil {
		fmt.Printf("Failed to generate markdown docs: %v\n", err)
		os.Exit(1)
	}

	// Generate man pages
	if err := os.MkdirAll(manDir, 0755); err != nil {
		fmt.Printf("Failed to create man directory: %v\n", err)
		os.Exit(1)
	}

	header := &doc.GenManHeader{
		Title:   "GOTLS",
		Section: "1",
	}
	if err := doc.GenManTree(rootCmd, header, manDir); err != nil {
		fmt.Printf("Failed to generate man pages: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Documentation generated successfully in %s\n", docsDir)
}

// findRepoRoot finds the repository root by looking for go.mod file
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding go.mod
			return "", fmt.Errorf("go.mod not found in any parent directory")
		}
		dir = parent
	}
}
