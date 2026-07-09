package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var appVersion = "dev"

func SetVersion(version string) {
	appVersion = version
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("tresor %s\n", appVersion)
			fmt.Println("Password-based CLI for encrypting and decrypting directory trees into .tre containers.")
			fmt.Println("License: MIT (see LICENSE)")
		},
	}
}

func init() {
	rootCmd.AddCommand(newVersionCmd())
}
