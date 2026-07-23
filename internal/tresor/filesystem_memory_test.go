package tresor

import (
	"bytes"
	"testing"

	"github.com/winfsp/cgofuse/fuse"
)

func TestMemoryFSCreateAndWrite(t *testing.T) {
	fs := NewMemoryFS()
	defer fs.Close()

	// Create a file
	errcode, fh := fs.Create("test.txt", 0, 0o666)
	if errcode != 0 {
		t.Fatalf("Create returned error: %d", errcode)
	}

	// Write to file
	data := []byte("hello world")
	n := fs.Write("test.txt", data, 0, fh)
	if n != len(data) {
		t.Fatalf("Write returned %d, want %d", n, len(data))
	}

	// Read back
	buf := make([]byte, 32)
	n = fs.Read("test.txt", buf, 0, 0)
	if n != len(data) {
		t.Fatalf("Read returned %d, want %d", n, len(data))
	}
	if !bytes.Equal(buf[:n], data) {
		t.Fatalf("Read data mismatch: got %q, want %q", buf[:n], data)
	}
}

func TestMemoryFSCreateDirectory(t *testing.T) {
	fs := NewMemoryFS()
	defer fs.Close()

	// Create directory
	errcode := fs.Mkdir("mydir", 0o755)
	if errcode != 0 {
		t.Fatalf("Mkdir returned error: %d", errcode)
	}

	// Verify directory exists
	var stat fuse.Stat_t
	errcode = fs.Getattr("mydir", &stat, 0)
	if errcode != 0 {
		t.Fatalf("Getattr returned error: %d", errcode)
	}
	if (stat.Mode & 0o40000) == 0 {
		t.Fatalf("Getattr: path is not a directory")
	}

	// Create file in directory
	errcode, _ = fs.Create("mydir/file.txt", 0, 0o666)
	if errcode != 0 {
		t.Fatalf("Create in subdir returned error: %d", errcode)
	}

	// Write to file in directory
	data := []byte("nested file")
	fs.Write("mydir/file.txt", data, 0, 0)

	// Read back
	buf := make([]byte, 32)
	n := fs.Read("mydir/file.txt", buf, 0, 0)
	if !bytes.Equal(buf[:n], data) {
		t.Fatalf("Nested file read mismatch")
	}
}

func TestMemoryFSReaddir(t *testing.T) {
	fs := NewMemoryFS()
	defer fs.Close()

	// Create some files
	fs.Create("file1.txt", 0, 0o666)
	fs.Create("file2.txt", 0, 0o666)
	fs.Mkdir("dir1", 0o755)
	fs.Mkdir("dir1/subdir", 0o755)
	fs.Create("dir1/file3.txt", 0, 0o666)

	// Read root directory
	entries := make(map[string]bool)
	fs.Readdir("/", func(name string, stat *fuse.Stat_t, ofst int64) bool {
		entries[name] = true
		return true
	}, 0, 0)

	if !entries["file1.txt"] {
		t.Fatalf("file1.txt not in readdir")
	}
	if !entries["file2.txt"] {
		t.Fatalf("file2.txt not in readdir")
	}
	if !entries["dir1"] {
		t.Fatalf("dir1 not in readdir")
	}

	// Read subdirectory
	entries = make(map[string]bool)
	fs.Readdir("dir1", func(name string, stat *fuse.Stat_t, ofst int64) bool {
		entries[name] = true
		return true
	}, 0, 0)

	if !entries["file3.txt"] {
		t.Fatalf("file3.txt not in dir1 readdir")
	}
	if !entries["subdir"] {
		t.Fatalf("subdir not in dir1 readdir")
	}
}

func TestMemoryFSDeleteFile(t *testing.T) {
	fs := NewMemoryFS()
	defer fs.Close()

	// Create and delete file
	fs.Create("test.txt", 0, 0o666)
	fs.Write("test.txt", []byte("data"), 0, 0)

	errcode := fs.Unlink("test.txt")
	if errcode != 0 {
		t.Fatalf("Unlink returned error: %d", errcode)
	}

	// Verify file is gone
	var stat fuse.Stat_t
	errcode = fs.Getattr("test.txt", &stat, 0)
	if errcode == 0 {
		t.Fatalf("Getattr succeeded on deleted file")
	}
}

func TestMemoryFSTruncate(t *testing.T) {
	fs := NewMemoryFS()
	defer fs.Close()

	// Create file and write data
	fs.Create("test.txt", 0, 0o666)
	fs.Write("test.txt", []byte("hello world"), 0, 0)

	// Truncate to 5 bytes
	errcode := fs.Truncate("test.txt", 5, 0)
	if errcode != 0 {
		t.Fatalf("Truncate returned error: %d", errcode)
	}

	// Read back - should only have "hello"
	buf := make([]byte, 32)
	n := fs.Read("test.txt", buf, 0, 0)
	if n != 5 {
		t.Fatalf("Read returned %d bytes, want 5", n)
	}
	if !bytes.Equal(buf[:n], []byte("hello")) {
		t.Fatalf("Truncated data mismatch: got %q, want %q", buf[:n], "hello")
	}
}

func TestMemoryFSFilePermissions(t *testing.T) {
	fs := NewMemoryFS()
	defer fs.Close()

	// Create file
	fs.Create("test.txt", 0, 0o666)

	// Check permissions are writable
	errcode := fs.Access("test.txt", 0o2)
	if errcode != 0 {
		t.Fatalf("Access check for write failed: %d", errcode)
	}

	// Check permissions are readable
	errcode = fs.Access("test.txt", 0o4)
	if errcode != 0 {
		t.Fatalf("Access check for read failed: %d", errcode)
	}
}

func TestMemoryFSWriteRespectsLimit(t *testing.T) {
	fs := NewMemoryFSWithLimit(8)
	defer fs.Close()

	errcode, fh := fs.Create("limit.txt", 0, 0o666)
	if errcode != 0 {
		t.Fatalf("Create returned error: %d", errcode)
	}

	if n := fs.Write("limit.txt", []byte("12345678"), 0, fh); n != 8 {
		t.Fatalf("Write returned %d, want 8", n)
	}

	if n := fs.Write("limit.txt", []byte("9"), 8, fh); n != -fuse.ENOSPC {
		t.Fatalf("Write over limit returned %d, want %d", n, -fuse.ENOSPC)
	}
}

func TestMemoryFSTruncateRespectsLimit(t *testing.T) {
	fs := NewMemoryFSWithLimit(5)
	defer fs.Close()

	errcode, fh := fs.Create("truncate.txt", 0, 0o666)
	if errcode != 0 {
		t.Fatalf("Create returned error: %d", errcode)
	}

	if n := fs.Write("truncate.txt", []byte("abc"), 0, fh); n != 3 {
		t.Fatalf("Write returned %d, want 3", n)
	}

	errcode = fs.Truncate("truncate.txt", 6, fh)
	if errcode != -fuse.ENOSPC {
		t.Fatalf("Truncate over limit returned %d, want %d", errcode, -fuse.ENOSPC)
	}
}
