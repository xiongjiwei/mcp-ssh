package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
// If a git tag exists: the tag (e.g. "v1.2.3").
// Otherwise: "branch@shortcommit" (e.g. "main@a1b2c3d").
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version and exit",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
