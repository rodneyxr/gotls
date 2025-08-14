package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// These variables are set at build time via -ldflags
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of GoTLS",
	Long:  `Print the version number of GoTLS`,
	Run: func(cmd *cobra.Command, args []string) {
		if version == "dev" {
			fmt.Printf("GoTLS %s (commit: %s, built: %s)\n", version, commit, date)
		} else {
			fmt.Printf("GoTLS v%s (commit: %s, built: %s)\n", version, commit, date)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
