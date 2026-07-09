package cli

import (
	"fmt"
	"os"
	"strings"

	"tresor/internal/tresor"

	"github.com/spf13/cobra"
)

type extractOptions struct {
	password  string
	file      string
	forceDirs bool
	conflict  string
}

func newExtractCmd() *cobra.Command {
	opts := &extractOptions{}

	cmd := &cobra.Command{
		Use:   "extract <path>",
		Short: "Extract a file or directory from container",
		Long: `Extract a file or directory from the container.

Examples:
  tresor extract input/bilder/text.txt        # Extract single file as text.txt
  tresor extract input/bilder                 # Extract all files from directory (flat)
  tresor extract input/bilder --force-dirs    # Extract all files preserving directory structure`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use default tresor.tre if no file specified
			if opts.file == "" {
				opts.file = "tresor.tre"
			}

			// Validate arguments and flags first, before prompting for password
			containerPath := ensureTreeExtension(opts.file)
			if _, err := os.Stat(containerPath); err != nil {
				return fmt.Errorf("container file %q: %w", containerPath, err)
			}

			handler, err := conflictHandlerFromFlag(opts.conflict)
			if err != nil {
				return err
			}

			// Now ask for password
			password, err := resolveDecryptPassword(opts.password)
			if err != nil {
				return err
			}

			// Normalize extract path (use forward slashes)
			extractPath := strings.ReplaceAll(args[0], "\\", "/")
			extractPath = strings.TrimSpace(extractPath)

			err = tresor.Extract(tresor.ExtractOptions{
				Password:       password,
				ContainerPath:  containerPath,
				ExtractPath:    extractPath,
				ForceDirs:      opts.forceDirs,
				OnFileConflict: handler,
				ProgressWriter: os.Stderr,
			})
			if err != nil {
				return err
			}

			fmt.Printf("extracted %q from container\n", extractPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for extraction")
	cmd.Flags().StringVar(&opts.file, "file", "", "Source container file path (.tre); defaults to tresor.tre")
	cmd.Flags().BoolVar(&opts.forceDirs, "force-dirs", false, "Preserve directory structure when extracting")
	cmd.Flags().StringVar(&opts.conflict, "on-conflict", "prompt", "Conflict behavior if target file exists: prompt|ignore|overwrite|rename")

	return cmd
}

func init() {
	rootCmd.AddCommand(newExtractCmd())
}
