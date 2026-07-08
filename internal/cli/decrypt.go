package cli

import (
	"fmt"
	"os"
	"strings"

	"tresor/internal/tresor"

	"github.com/spf13/cobra"
)

type decryptOptions struct {
	password string
	remove   bool
	file     string
	conflict string
}

func newDecryptCmd() *cobra.Command {
	opts := &decryptOptions{}

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Recursively decrypt a container file into directories in the working directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := resolveDecryptPassword(opts.password)
			if err != nil {
				return err
			}

			handler, err := conflictHandlerFromFlag(opts.conflict)
			if err != nil {
				return err
			}

			err = tresor.Decrypt(tresor.DecryptOptions{
				Password:        password,
				ContainerPath:   opts.file,
				RemoveContainer: opts.remove,
				OnFileConflict:  handler,
				ProgressWriter:  os.Stderr,
			})
			if err != nil {
				return err
			}

			fmt.Printf("decrypted container %q into current working directory\n", opts.file)
			if opts.remove {
				fmt.Println("container file was removed after successful decryption")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for decryption")
	cmd.Flags().BoolVar(&opts.remove, "remove", false, "Remove container file after successful decryption")
	cmd.Flags().StringVar(&opts.file, "file", "", "Source container file path (.tre)")
	cmd.Flags().StringVar(&opts.conflict, "on-conflict", "prompt", "Conflict behavior if target file exists: prompt|ignore|overwrite|rename")

	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func conflictHandlerFromFlag(mode string) (tresor.FileConflictHandler, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "prompt":
		return nil, nil
	case "ignore":
		return func(targetPath string) (tresor.FileConflictAction, error) {
			return tresor.ConflictIgnore, nil
		}, nil
	case "overwrite":
		return func(targetPath string) (tresor.FileConflictAction, error) {
			return tresor.ConflictOverwrite, nil
		}, nil
	case "rename", "change":
		return func(targetPath string) (tresor.FileConflictAction, error) {
			return tresor.ConflictRename, nil
		}, nil
	default:
		return nil, fmt.Errorf("invalid --on-conflict value %q (use: prompt|ignore|overwrite|rename)", mode)
	}
}

func init() {
	rootCmd.AddCommand(newDecryptCmd())
}
