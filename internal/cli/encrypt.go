package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

type encryptOptions struct {
	password string
	remove   bool
	file     string
}

func newEncryptCmd() *cobra.Command {
	opts := &encryptOptions{}

	cmd := &cobra.Command{
		Use:   "encrypt [paths...]",
		Short: "Recursively encrypt one or more directories into a container file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("[stub] encrypt called with file=%q remove=%t paths=%v\n", opts.file, opts.remove, args)
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for encryption")
	cmd.Flags().BoolVar(&opts.remove, "remove", false, "Remove source files/directories after successful encryption")
	cmd.Flags().StringVar(&opts.file, "file", "", "Target container file path (.tre)")

	_ = cmd.MarkFlagRequired("password")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func init() {
	rootCmd.AddCommand(newEncryptCmd())
}
