//go:build windows

package cli

import (
	"bytes"
	"strings"
	"testing"

	"tresor/internal/tresor"

	"github.com/winfsp/cgofuse/fuse"
)

func TestGetVolumeLabelRemovesTreExtension(t *testing.T) {
	got := getVolumeLabel("C:/tmp/myvault.tre")
	if got != "myvault" {
		t.Fatalf("getVolumeLabel() = %q, want %q", got, "myvault")
	}
}

func TestGetVolumeLabelTruncatesTo32Chars(t *testing.T) {
	got := getVolumeLabel("C:/tmp/abcdefghijklmnopqrstuvwxyz1234567890.tre")
	if len(got) != 32 {
		t.Fatalf("len(getVolumeLabel()) = %d, want 32", len(got))
	}
}

func TestBuildMountOptionsReadOnly(t *testing.T) {
	opts := buildMountOptions("vault", false)

	if len(opts) == 0 {
		t.Fatal("buildMountOptions() returned empty options")
	}
	if opts[0] == "-f" {
		t.Fatal("read-only options must not include -f")
	}
	joined := strings.Join(opts, " ")
	if !strings.Contains(joined, "allow_other") {
		t.Fatal("read-only options missing allow_other")
	}
	if !strings.Contains(joined, "FileSystemName=NTFS") {
		t.Fatal("read-only options missing FileSystemName=NTFS")
	}
	if !strings.Contains(joined, "volname=vault") {
		t.Fatal("read-only options missing volname")
	}
}

func TestBuildMountOptionsReadWrite(t *testing.T) {
	opts := buildMountOptions("vault", true)

	if len(opts) < 1 {
		t.Fatal("buildMountOptions() returned empty options")
	}
	if opts[0] != "-f" {
		t.Fatalf("read-write options first arg = %q, want %q", opts[0], "-f")
	}
	joined := strings.Join(opts, " ")
	if !strings.Contains(joined, "FileSystemName=NTFS") {
		t.Fatal("read-write options missing FileSystemName=NTFS")
	}
	if !strings.Contains(joined, "volname=vault") {
		t.Fatal("read-write options missing volname")
	}
}

func TestNewMountCmdReadWriteFlagExists(t *testing.T) {
	cmd := newMountCmd()
	flag := cmd.Flags().Lookup("read-write")
	if flag == nil {
		t.Fatal("flag --read-write not found")
	}
	if flag.Shorthand != "w" {
		t.Fatalf("--read-write shorthand = %q, want %q", flag.Shorthand, "w")
	}
}

func TestReadWriteFilesystemMountAndCopyToRoot(t *testing.T) {
	rwfs := tresor.NewMemoryFS()
	defer rwfs.Close()

	// Simulate mount wiring used by mount --read-write.
	host := fuse.NewFileSystemHost(rwfs)
	if host == nil {
		t.Fatal("NewFileSystemHost returned nil")
	}

	content := []byte("copied from host")
	errCode, fh := rwfs.Create("copied.txt", 0, 0o644)
	if errCode != 0 {
		t.Fatalf("Create(copied.txt) error = %d", errCode)
	}

	written := rwfs.Write("copied.txt", content, 0, fh)
	if written != len(content) {
		t.Fatalf("Write() bytes = %d, want %d", written, len(content))
	}

	buf := make([]byte, len(content))
	read := rwfs.Read("copied.txt", buf, 0, fh)
	if read != len(content) {
		t.Fatalf("Read() bytes = %d, want %d", read, len(content))
	}
	if !bytes.Equal(buf, content) {
		t.Fatalf("Read() data = %q, want %q", string(buf), string(content))
	}
}
