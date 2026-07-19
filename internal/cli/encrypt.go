package cli

import (
	"fmt"
	"os"

	"tresor/internal/tresor"

	"github.com/spf13/cobra"
)

type encryptOptions struct {
	password     string
	remove       bool
	secureRemove bool
	file         string
	ifExists     string
	conflict     string
	maxSize      int64
}

func newEncryptCmd() *cobra.Command {
	opts := &encryptOptions{}

	cmd := &cobra.Command{
		Use:   "encrypt [paths...]",
		Short: "Recursively encrypt one or more directories into a container file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use default tresor.tre if no file specified
			if opts.file == "" {
				opts.file = "tresor.tre"
			}

			// Validate arguments and flags first, before prompting for password
			handler, err := conflictHandlerFromFlag(opts.conflict)
			if err != nil {
				return err
			}

			// Now ask for password
			password, err := resolveEncryptPassword(opts.password)
			if err != nil {
				return err
			}

			containerPath := ensureTreeExtension(opts.file)
			maxSizeBytes := opts.maxSize * 1024 * 1024 // Convert MB to bytes
			err = tresor.Encrypt(tresor.EncryptOptions{
				Password:         password,
				ContainerPath:    containerPath,
				Inputs:           args,
				RemoveSources:    opts.remove,
				SecureRemove:     opts.secureRemove,
				IfExists:         opts.ifExists,
				OnFileConflict:   handler,
				MaxContainerSize: maxSizeBytes,
				ProgressWriter:   os.Stderr,
			})
			if err != nil {
				return err
			}

			fmt.Printf("encrypted %d input path(s) into %q\n", len(args), containerPath)
			if opts.remove {
				if opts.secureRemove {
					fmt.Println("source paths were securely removed (Gutmann method, 3 passes)")
				} else {
					fmt.Println("source paths were removed after successful encryption")
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.password, "password", "p", "", "Password used for encryption")
	cmd.Flags().BoolVarP(&opts.remove, "remove", "r", false, "Remove source paths after successful encryption")
	cmd.Flags().BoolVar(&opts.secureRemove, "secure-remove", false, "Use Gutmann method (3 passes) for secure deletion; requires --remove")
	cmd.Flags().StringVarP(&opts.file, "file", "f", "", "Target container file path (.tre); defaults to tresor.tre")
	cmd.Flags().StringVar(&opts.ifExists, "if-exists", "sync", "Behavior if target container exists: sync|append")
	cmd.Flags().StringVar(&opts.conflict, "on-conflict", "prompt", "Conflict behavior in append mode: prompt|ignore|overwrite|rename")
	cmd.Flags().Int64Var(&opts.maxSize, "max-size", 0, "Maximum size per container file in MB (0 = unlimited, all data in single file)")

	return cmd
}

func init() {
	rootCmd.AddCommand(newEncryptCmd())
}
