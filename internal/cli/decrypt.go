package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

type decryptOptions struct {
	password string
	remove   bool
	file     string
}

func newDecryptCmd() *cobra.Command {
	opts := &decryptOptions{}

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Recursively decrypt a container file into directories in the working directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("[stub] decrypt called with file=%q remove=%t\n", opts.file, opts.remove)
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for decryption")
	cmd.Flags().BoolVar(&opts.remove, "remove", false, "Remove container file after successful decryption")
	cmd.Flags().StringVar(&opts.file, "file", "", "Source container file path (.tre)")

	_ = cmd.MarkFlagRequired("password")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func init() {
	rootCmd.AddCommand(newDecryptCmd())
}
