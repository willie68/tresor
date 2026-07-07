package cli

import (
	"fmt"

	"tresor/internal/tresor"

	"github.com/spf13/cobra"
)

type encryptOptions struct {
	password string
	remove   bool
	file     string
	ifExists string
	conflict string
}

func newEncryptCmd() *cobra.Command {
	opts := &encryptOptions{}

	cmd := &cobra.Command{
		Use:   "encrypt [paths...]",
		Short: "Recursively encrypt one or more directories into a container file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := resolveEncryptPassword(opts.password)
			if err != nil {
				return err
			}

			handler, err := conflictHandlerFromFlag(opts.conflict)
			if err != nil {
				return err
			}

			err = tresor.Encrypt(tresor.EncryptOptions{
				Password:       password,
				ContainerPath:  opts.file,
				Inputs:         args,
				RemoveSources:  opts.remove,
				IfExists:       opts.ifExists,
				OnFileConflict: handler,
			})
			if err != nil {
				return err
			}

			fmt.Printf("encrypted %d input path(s) into %q\n", len(args), opts.file)
			if opts.remove {
				fmt.Println("source paths were removed after successful encryption")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for encryption")
	cmd.Flags().BoolVar(&opts.remove, "remove", false, "Remove source files/directories after successful encryption")
	cmd.Flags().StringVar(&opts.file, "file", "", "Target container file path (.tre)")
	cmd.Flags().StringVar(&opts.ifExists, "if-exists", "sync", "Behavior if target container exists: sync|append")
	cmd.Flags().StringVar(&opts.conflict, "on-conflict", "prompt", "Conflict behavior in append mode: prompt|ignore|overwrite|change")

	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func init() {
	rootCmd.AddCommand(newEncryptCmd())
}
