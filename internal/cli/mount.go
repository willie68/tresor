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
}

func newMountCmd() *cobra.Command {
	opts := &mountOptions{}

	cmd := &cobra.Command{
		Use:   "mount <mount-point>",
		Short: "Mount a tresor container file as a read-only filesystem",
		Long:  "Mount a tresor container file as a read-only filesystem using FUSE",
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

			// Create the filesystem
			fs, err := tresor.NewReadOnlyFS(containerPath, password, cacheSizeBytes)
			if err != nil {
				return fmt.Errorf("create filesystem: %w", err)
			}
			defer fs.Close()

			// Mount the filesystem
			host := fuse.NewFileSystemHost(fs)

			// Extract volume label from container filename (without extension)
			volumeLabel := filepath.Base(containerPath)
			if strings.HasSuffix(strings.ToLower(volumeLabel), ".tre") {
				volumeLabel = volumeLabel[:len(volumeLabel)-4]
			}
			// Truncate to 32 chars max for Windows compatibility
			if len(volumeLabel) > 32 {
				volumeLabel = volumeLabel[:32]
			}

			os.Setenv("FSP_FUSE_VOLUME_NAME", volumeLabel)
			// Create mount options with volume label and capacity hints
			mountOptions := []string{
				//"-o", fmt.Sprintf("VolumeName=%s", volumeLabel),
				"-o", "allow_other",
				"-o", "uid=500,gid=500",
				"-o", "FileSystemName=NTFS", // Täuscht ein Standard-Dateisystem vor
				"-o", fmt.Sprintf("volname=%s", volumeLabel),
			}

			fmt.Printf("mounted %q at %q (read-only)\n", containerPath, mountPoint)
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

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for decryption")
	cmd.Flags().StringVar(&opts.file, "file", "", "Container file path (.tre); defaults to tresor.tre")
	cmd.Flags().Int64Var(&opts.cacheSize, "cache-size", 0, "Cache size in MB (0 = no cache, default = 0)")

	return cmd
}

func init() {
	rootCmd.AddCommand(newMountCmd())
}
