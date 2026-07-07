package cli

import (
	"fmt"

	"tresor/internal/tresor"

	"github.com/spf13/cobra"
)

type listOptions struct {
	password string
	file     string
}

func newListCmd() *cobra.Command {
	opts := &listOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List container contents with full output paths",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := resolveDecryptPassword(opts.password)
			if err != nil {
				return err
			}

			entries, err := tresor.List(tresor.ListOptions{
				Password:      password,
				ContainerPath: opts.file,
			})
			if err != nil {
				return err
			}

			for _, entry := range entries {
				if entry.IsDir {
					fmt.Printf("<DIR>          %s\n", entry.Path)
					continue
				}
				fmt.Printf("%14d %s\n", entry.Size, entry.Path)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for listing")
	cmd.Flags().StringVar(&opts.file, "file", "", "Source container file path (.tre)")

	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func init() {
	rootCmd.AddCommand(newListCmd())
}
