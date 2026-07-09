package main

import "tresor/internal/cli"

// Version is set via ldflags during build (e.g., by goreleaser)
var Version = "dev"

func main() {
	cli.SetVersion(Version)
	cli.Execute()
}
