package tresor

import (
	"bytes"
	"testing"

	"github.com/winfsp/cgofuse/fuse"
)

func TestFUSEReadSmallFile(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create small test file (like the .fdhashes3 example)
		testData := []byte("small test file content")
		mustWriteFile(t, "test.txt", testData)

		// Encrypt
		containerPath := "test.tre"
		err := Encrypt(EncryptOptions{
			Password:      "topsecret",
			ContainerPath: containerPath,
			Inputs:        []string{"test.txt"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// Create ReadOnlyFS with cache
		fs, err := NewReadOnlyFS(containerPath, "topsecret", 10*1024*1024)
		if err != nil {
			t.Fatalf("NewReadOnlyFS failed: %v", err)
		}
		defer fs.Close()

		// Simulate FUSE Getattr call
		var stat fuse.Stat_t
		errcode := fs.Getattr("test.txt", &stat, 0)
		if errcode != 0 {
			t.Errorf("Getattr returned error: %d", errcode)
		}
		if stat.Size != int64(len(testData)) {
			t.Errorf("Getattr size mismatch: got %d, want %d", stat.Size, len(testData))
		}

		// Simulate FUSE Read call with large buffer (like 4KB or 64KB)
		buff := make([]byte, 4096)
		n := fs.Read("test.txt", buff, 0, 0)
		if n < 0 {
			t.Fatalf("Read returned error: %d", n)
		}
		if n != len(testData) {
			t.Errorf("Read returned %d bytes, want %d", n, len(testData))
		}
		if !bytes.Equal(buff[:n], testData) {
			t.Errorf("Read data mismatch.\nGot:  %q\nWant: %q", buff[:n], testData)
		}

		// Test partial reads
		buff = make([]byte, 5)
		n = fs.Read("test.txt", buff, 0, 0)
		if n != 5 {
			t.Errorf("Partial read returned %d bytes, want 5", n)
		}
		if !bytes.Equal(buff[:n], testData[:5]) {
			t.Errorf("Partial read mismatch.\nGot:  %q\nWant: %q", buff[:n], testData[:5])
		}

		// Test read at offset
		offset := int64(6)
		buff = make([]byte, 4096)
		n = fs.Read("test.txt", buff, offset, 0)
		expected := testData[offset:]
		if n != len(expected) {
			t.Errorf("Read at offset %d returned %d bytes, want %d", offset, n, len(expected))
		}
		if !bytes.Equal(buff[:n], expected) {
			t.Errorf("Read at offset %d mismatch.\nGot:  %q\nWant: %q", offset, buff[:n], expected)
		}
	})
}

func TestFUSEReadVerySmallFile(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Very tiny file (like .fdhashes3 which is JSON)
		testData := []byte("F3")
		mustWriteFile(t, "tiny.txt", testData)

		containerPath := "test.tre"
		err := Encrypt(EncryptOptions{
			Password:      "topsecret",
			ContainerPath: containerPath,
			Inputs:        []string{"tiny.txt"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		fs, err := NewReadOnlyFS(containerPath, "topsecret", 10*1024*1024)
		if err != nil {
			t.Fatalf("NewReadOnlyFS failed: %v", err)
		}
		defer fs.Close()

		buff := make([]byte, 4096)
		n := fs.Read("tiny.txt", buff, 0, 0)
		if n < 0 {
			t.Fatalf("Read returned error: %d", n)
		}
		if n != len(testData) {
			t.Errorf("Read returned %d bytes, want %d", n, len(testData))
		}
		if !bytes.Equal(buff[:n], testData) {
			t.Errorf("Read data mismatch.\nGot:  %q\nWant: %q", buff[:n], testData)
		}
	})
}
