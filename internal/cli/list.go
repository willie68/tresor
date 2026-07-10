package cli

import (
	"fmt"
	"time"

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
			// Use default tresor.tre if no file specified
			if opts.file == "" {
				opts.file = "tresor.tre"
			}

			password, err := resolveDecryptPassword(opts.password)
			if err != nil {
				return err
			}

			containerPath := ensureTreeExtension(opts.file)
			entries, err := tresor.List(tresor.ListOptions{
				Password:      password,
				ContainerPath: containerPath,
			})
			if err != nil {
				return err
			}

			fileCount := 0
			dirCount := 0
			var totalBytes int64

			// Print header
			fmt.Printf("%-6s %20s %10s %-s\n", "Mode", "LastWriteTime", "Length", "Name")
			fmt.Printf("%-6s %20s %10s %-s\n", "----", "-------------", "------", "----")

			for _, entry := range entries {
				mode := "-a----"
				if entry.IsDir {
					mode = "d-----"
					dirCount++
				} else {
					fileCount++
					totalBytes += entry.Size
				}

				var modTime string
				if entry.ModTime != 0 {
					modTime = time.Unix(entry.ModTime, 0).Format("02.01.2006     15:04")
				} else {
					modTime = "                  "
				}

				length := ""
				if !entry.IsDir {
					length = fmt.Sprintf("%d", entry.Size)
				}

				fmt.Printf("%-6s %20s %10s %s\n", mode, modTime, length, entry.Path)
			}

			fmt.Printf("%14d File(s) %d bytes\n", fileCount, totalBytes)
			fmt.Printf("%14d Dir(s)\n", dirCount)
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for listing")
	cmd.Flags().StringVar(&opts.file, "file", "", "Source container file path (.tre); defaults to tresor.tre")

	return cmd
}

func init() {
	rootCmd.AddCommand(newListCmd())
}
