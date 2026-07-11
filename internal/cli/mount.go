package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tresor/internal/tresor"

	"github.com/spf13/cobra"
	"github.com/winfsp/cgofuse/fuse"
)

type mountOptions struct {
	password string
	file     string
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

			// Create the filesystem
			fs, err := tresor.NewReadOnlyFS(containerPath, password)
			if err != nil {
				return fmt.Errorf("create filesystem: %w", err)
			}
			defer fs.Close()

			// Mount the filesystem
			host := fuse.NewFileSystemHost(fs)

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

			// Block on Mount - will return when unmounted by signal handler
			if !host.Mount(mountPoint, nil) {
				return fmt.Errorf("failed to mount at %s", mountPoint)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&opts.password, "password", "", "Password used for decryption")
	cmd.Flags().StringVar(&opts.file, "file", "", "Container file path (.tre); defaults to tresor.tre")

	return cmd
}

func init() {
	rootCmd.AddCommand(newMountCmd())
}
