//go:build windows

package cli

import (
	"strings"
	"testing"
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
	opts := buildMountOptions("vault")

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
