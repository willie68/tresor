package cli

import (
	"fmt"
	"runtime"
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

			// Use platform-specific output format
			switch runtime.GOOS {
			case "linux":
				formatListLinux(entries)
			case "darwin":
				formatListDarwin(entries)
			default: // windows and others
				formatListWindows(entries)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for listing")
	cmd.Flags().StringVar(&opts.file, "file", "", "Source container file path (.tre); defaults to tresor.tre")

	return cmd
}

// formatListWindows displays output in PowerShell dir-like format
func formatListWindows(entries []tresor.ListedEntry) {
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
}

// formatListLinux displays output in ls -l style format
func formatListLinux(entries []tresor.ListedEntry) {
	fileCount := 0
	dirCount := 0
	var totalBytes int64

	for _, entry := range entries {
		// Determine type and permissions (using default permissions since not stored in container)
		var typeChar string
		var mode string
		if entry.IsDir {
			typeChar = "d"
			mode = "rwxr-xr-x"
			dirCount++
		} else {
			typeChar = "-"
			mode = "rw-r--r--"
			fileCount++
			totalBytes += entry.Size
		}

		// Format: drwxr-xr-x 1 user group size date time name
		var modTime string
		if entry.ModTime != 0 {
			modTime = time.Unix(entry.ModTime, 0).Format("Jan 02 15:04")
		} else {
			modTime = "Jan 01 00:00"
		}

		size := ""
		if !entry.IsDir {
			size = fmt.Sprintf("%d", entry.Size)
		}

		fmt.Printf("%s%s 1 user group %8s %12s %s\n", typeChar, mode, size, modTime, entry.Path)
	}

	fmt.Printf("total %d\n", fileCount+dirCount)
}

// formatListDarwin displays output in Darwin (macOS) ls -l style format
func formatListDarwin(entries []tresor.ListedEntry) {
	fileCount := 0
	dirCount := 0
	var totalBytes int64

	for _, entry := range entries {
		// Determine type and permissions (using default permissions since not stored in container)
		var typeChar string
		var mode string
		if entry.IsDir {
			typeChar = "d"
			mode = "rwxr-xr-x"
			dirCount++
		} else {
			typeChar = "-"
			mode = "rw-r--r--"
			fileCount++
			totalBytes += entry.Size
		}

		// Format: drwxr-xr-x 1 user group size date time name
		var modTime string
		if entry.ModTime != 0 {
			t := time.Unix(entry.ModTime, 0)
			if time.Since(t) < 6*30*24*time.Hour { // Last 6 months
				modTime = t.Format("Jan 02 15:04")
			} else {
				modTime = t.Format("Jan 02  2006")
			}
		} else {
			modTime = "Jan 01 00:00"
		}

		size := ""
		if !entry.IsDir {
			size = fmt.Sprintf("%d", entry.Size)
		}

		fmt.Printf("%s%s 1 user group %8s %12s %s\n", typeChar, mode, size, modTime, entry.Path)
	}

	fmt.Printf("total %d\n", fileCount+dirCount)
}

func init() {
	rootCmd.AddCommand(newListCmd())
}
