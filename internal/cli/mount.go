//go:build windows

package cli

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"tresor/internal/tresor"

	"github.com/spf13/cobra"
	"github.com/winfsp/cgofuse/fuse"
)

type mountOptions struct {
	password  string
	file      string
	cacheSize int64 // Cache size in MB, 0 = no cache
	readWrite bool  // Enable read-write mode
}

func newMountCmd() *cobra.Command {
	opts := &mountOptions{}

	cmd := &cobra.Command{
		Use:   "mount <mount-point>",
		Short: "Mount a tresor container file as a filesystem (read-only or read-write)",
		Long:  "Mount a tresor container file as a filesystem using FUSE. Use --read-write flag to enable write mode.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mountPoint := args[0]

			// Use default tresor.tre if no file specified
			if opts.file == "" {
				opts.file = "tresor.tre"
			}

			// Now ask for password
			password, err := resolveDecryptPassword(opts.password)
			if err != nil {
				return err
			}

			containerPath := ensureTreeExtension(opts.file)

			// Convert cache size from MB to bytes
			cacheSizeBytes := opts.cacheSize * 1024 * 1024

			// Extract volume label from container filename (without extension)
			volumeLabel := filepath.Base(containerPath)
			if strings.HasSuffix(strings.ToLower(volumeLabel), ".tre") {
				volumeLabel = volumeLabel[:len(volumeLabel)-4]
			}
			// Truncate to 32 chars max for Windows compatibility
			if len(volumeLabel) > 32 {
				volumeLabel = volumeLabel[:32]
			}

			var host *fuse.FileSystemHost
			var mountOptions []string

			if opts.readWrite {
				// Read-write mode
				rwfs, err := tresor.NewReadWriteFS(containerPath, password, cacheSizeBytes)
				if err != nil {
					return fmt.Errorf("create filesystem: %w", err)
				}
				defer rwfs.Close()

				host = fuse.NewFileSystemHost(rwfs)

				// Mount options for read-write mode
				mountOptions = []string{
					"-o", "allow_other",
					"-o", fmt.Sprintf("volname=%s", volumeLabel),
				}
			} else {
				// Read-only mode
				rofs, err := tresor.NewReadOnlyFS(containerPath, password, cacheSizeBytes)
				if err != nil {
					return fmt.Errorf("create filesystem: %w", err)
				}
				defer rofs.Close()

				host = fuse.NewFileSystemHost(rofs)

				// Mount options for read-only mode (original settings)
				mountOptions = []string{
					"-o", "allow_other",
					"-o", "uid=500,gid=500",
					"-o", "FileSystemName=NTFS",
					"-o", fmt.Sprintf("volname=%s", volumeLabel),
				}
			}

			os.Setenv("FSP_FUSE_VOLUME_NAME", volumeLabel)

			mode := "read-only"
			if opts.readWrite {
				mode = "read-write"
			}
			fmt.Printf("mounted %q at %q (%s)\n", containerPath, mountPoint, mode)
			fmt.Println("Press Ctrl+C to unmount")
			os.Stdout.Sync()

			// Setup signal handler to unmount
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigChan
				host.Unmount()
			}()

			// Recover from panic if WinFSP is not installed
			defer func() {
				if r := recover(); r != nil {
					panicMsg := fmt.Sprintf("%v", r)
					if strings.Contains(panicMsg, "cannot find winfsp") {
						fmt.Fprintf(os.Stderr, "\nError: WinFSP is not installed.\n")
						fmt.Fprintf(os.Stderr, "Please install WinFSP from: https://github.com/winfsp/winfsp/releases\n")
						os.Exit(1)
					}
					panic(r)
				}
			}()

			// Block on Mount - will return when unmounted by signal handler
			if !host.Mount(mountPoint, mountOptions) {
				return fmt.Errorf("failed to mount at %s", mountPoint)
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&opts.readWrite, "read-write", "w", false, "Enable read-write mode instead of read-only")

	cmd.Flags().StringVarP(&opts.password, "password", "p", "", "Password used for decryption")
	cmd.Flags().StringVarP(&opts.file, "file", "f", "", "Container file path (.tre); defaults to tresor.tre")
	cmd.Flags().Int64Var(&opts.cacheSize, "cache-size", 0, "Cache size in MB (0 = no cache, default = 0)")

	return cmd
}

func init() {
	rootCmd.AddCommand(newMountCmd())
}
