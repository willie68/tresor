package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tresor",
	Short: "Encrypt and decrypt directory trees into a container file",
	Long:  "tresor is a CLI stub that will recursively encrypt and decrypt directory trees into a .tre container file.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
