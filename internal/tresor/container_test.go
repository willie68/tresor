package tresor

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("mongodump", "dump1.bson"), []byte("dump-content-1"))
		mustWriteFile(t, filepath.Join("minio", "objects", "obj1.bin"), []byte("object-content-1"))

		err := Encrypt(EncryptOptions{
			Password:      "topsecret",
			ContainerPath: "vault.tre",
			Inputs:        []string{"mongodump", "minio"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		if err := os.RemoveAll("mongodump"); err != nil {
			t.Fatalf("remove mongodump: %v", err)
		}
		if err := os.RemoveAll("minio"); err != nil {
			t.Fatalf("remove minio: %v", err)
		}

		err = Decrypt(DecryptOptions{
			Password:      "topsecret",
			ContainerPath: "vault.tre",
		})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("mongodump", "dump1.bson"), []byte("dump-content-1"))
		assertFileContent(t, filepath.Join("minio", "objects", "obj1.bin"), []byte("object-content-1"))
	})
}

func TestEncryptDecryptRemoveFlags(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("data", "x.txt"), []byte("remove-me"))

		err := Encrypt(EncryptOptions{
			Password:      "pw",
			ContainerPath: "vault.tre",
			Inputs:        []string{"data"},
			RemoveSources: true,
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		if _, err := os.Stat("data"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected source directory to be removed, got err=%v", err)
		}

		err = Decrypt(DecryptOptions{
			Password:        "pw",
			ContainerPath:   "vault.tre",
			RemoveContainer: true,
		})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("data", "x.txt"), []byte("remove-me"))
		if _, err := os.Stat("vault.tre"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected container to be removed, got err=%v", err)
		}
	})
}

func TestContainerHasNoPlaintextMetadataOrContent(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		nameA := "very-secret-folder"
		nameB := "hidden-filename.txt"
		content := "ULTRA_SECRET_CONTENT_12345"
		mustWriteFile(t, filepath.Join(nameA, nameB), []byte(content))

		err := Encrypt(EncryptOptions{
			Password:      "pw-plaintext-test",
			ContainerPath: "vault.tre",
			Inputs:        []string{nameA},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		containerData, err := os.ReadFile("vault.tre")
		if err != nil {
			t.Fatalf("read container: %v", err)
		}

		terms := []string{nameA, nameB, content}
		for _, term := range terms {
			if bytes.Contains(containerData, []byte(term)) {
				t.Fatalf("container unexpectedly contains plaintext term %q", term)
			}
		}
	})
}

func TestDecryptWrongPasswordFails(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("data"))

		err := Encrypt(EncryptOptions{
			Password:      "correct-password",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		if err := os.RemoveAll("src"); err != nil {
			t.Fatalf("remove source: %v", err)
		}

		err = Decrypt(DecryptOptions{
			Password:      "wrong-password",
			ContainerPath: "vault.tre",
		})
		if err == nil {
			t.Fatal("expected decrypt to fail with wrong password")
		}
		if !strings.Contains(err.Error(), "invalid password or corrupted container") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}

func TestDecryptTamperedContainerFails(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("data"))
		err := Encrypt(EncryptOptions{
			Password:      "tamper-test",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		b, err := os.ReadFile("vault.tre")
		if err != nil {
			t.Fatalf("read container: %v", err)
		}
		b[len(b)-1] ^= 0xFF
		if err := os.WriteFile("vault.tre", b, 0o644); err != nil {
			t.Fatalf("write tampered container: %v", err)
		}

		err = Decrypt(DecryptOptions{
			Password:      "tamper-test",
			ContainerPath: "vault.tre",
		})
		if err == nil {
			t.Fatal("expected decrypt to fail for tampered container")
		}
	})
}

func TestCompressionDecisionInIndex(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		compressible := bytes.Repeat([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 4096)
		incompressible := make([]byte, 64*1024)
		if _, err := crand.Read(incompressible); err != nil {
			t.Fatalf("generate random test bytes: %v", err)
		}

		mustWriteFile(t, filepath.Join("src", "compressible.txt"), compressible)
		mustWriteFile(t, filepath.Join("src", "incompressible.bin"), incompressible)

		err := Encrypt(EncryptOptions{
			Password:      "pw-compression",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		idx, err := readDecryptedIndex("vault.tre", "pw-compression")
		if err != nil {
			t.Fatalf("read decrypted index: %v", err)
		}

		var compressedEntry *archiveEntry
		var incompressedEntry *archiveEntry
		for i := range idx.Entries {
			e := &idx.Entries[i]
			if e.Type != entryTypeFile {
				continue
			}
			switch filepath.Base(e.Path) {
			case "compressible.txt":
				compressedEntry = e
			case "incompressible.bin":
				incompressedEntry = e
			}
		}

		if compressedEntry == nil || incompressedEntry == nil {
			t.Fatal("did not find expected file entries in index")
		}

		if !compressedEntry.Compressed {
			t.Fatal("expected compressible file to be stored compressed")
		}
		if compressedEntry.StoredSize <= 0 || compressedEntry.StoredSize >= compressedEntry.Size {
			t.Fatalf("unexpected stored size for compressed file: stored=%d original=%d", compressedEntry.StoredSize, compressedEntry.Size)
		}

		if incompressedEntry.Compressed {
			t.Fatal("expected incompressible file to be stored without compression")
		}
		if incompressedEntry.StoredSize != incompressedEntry.Size {
			t.Fatalf("expected stored size to match original for incompressible file: stored=%d original=%d", incompressedEntry.StoredSize, incompressedEntry.Size)
		}
	})
}

func TestDecryptConflictIgnore(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("from-container"))
		err := Encrypt(EncryptOptions{
			Password:      "pw-ignore",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("already-there"))

		err = Decrypt(DecryptOptions{
			Password:      "pw-ignore",
			ContainerPath: "vault.tre",
			OnFileConflict: func(targetPath string) (FileConflictAction, error) {
				return ConflictIgnore, nil
			},
		})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("src", "file.txt"), []byte("already-there"))
	})
}

func TestDecryptConflictOverwrite(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("from-container"))
		err := Encrypt(EncryptOptions{
			Password:      "pw-overwrite",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("already-there"))

		err = Decrypt(DecryptOptions{
			Password:      "pw-overwrite",
			ContainerPath: "vault.tre",
			OnFileConflict: func(targetPath string) (FileConflictAction, error) {
				return ConflictOverwrite, nil
			},
		})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("src", "file.txt"), []byte("from-container"))
	})
}

func TestDecryptConflictChange(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("from-container"))
		err := Encrypt(EncryptOptions{
			Password:      "pw-change",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("already-there"))

		err = Decrypt(DecryptOptions{
			Password:      "pw-change",
			ContainerPath: "vault.tre",
			OnFileConflict: func(targetPath string) (FileConflictAction, error) {
				return ConflictChange, nil
			},
		})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("src", "file.txt"), []byte("already-there"))
		assertFileContent(t, filepath.Join("src", "file (0001).txt"), []byte("from-container"))
	})
}

func TestEncryptAppendAddsOnlyNewFiles(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("src", "a.txt"), []byte("A1"))
		err := Encrypt(EncryptOptions{
			Password:      "pw-append",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("initial encrypt failed: %v", err)
		}

		mustWriteFile(t, filepath.Join("src", "b.txt"), []byte("B1"))
		err = Encrypt(EncryptOptions{
			Password:      "pw-append",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
			IfExists:      "append",
			OnFileConflict: func(targetPath string) (FileConflictAction, error) {
				return ConflictIgnore, nil
			},
		})
		if err != nil {
			t.Fatalf("append encrypt failed: %v", err)
		}

		if err := os.RemoveAll("src"); err != nil {
			t.Fatalf("remove src: %v", err)
		}
		err = Decrypt(DecryptOptions{Password: "pw-append", ContainerPath: "vault.tre"})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("src", "a.txt"), []byte("A1"))
		assertFileContent(t, filepath.Join("src", "b.txt"), []byte("B1"))
	})
}

func TestEncryptAppendConflictOverwrite(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("src", "same.txt"), []byte("OLD"))
		err := Encrypt(EncryptOptions{
			Password:      "pw-overwrite-append",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("initial encrypt failed: %v", err)
		}

		mustWriteFile(t, filepath.Join("src", "same.txt"), []byte("NEW"))
		err = Encrypt(EncryptOptions{
			Password:      "pw-overwrite-append",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
			IfExists:      "append",
			OnFileConflict: func(targetPath string) (FileConflictAction, error) {
				return ConflictOverwrite, nil
			},
		})
		if err != nil {
			t.Fatalf("append overwrite failed: %v", err)
		}

		if err := os.RemoveAll("src"); err != nil {
			t.Fatalf("remove src: %v", err)
		}
		err = Decrypt(DecryptOptions{Password: "pw-overwrite-append", ContainerPath: "vault.tre"})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("src", "same.txt"), []byte("NEW"))
	})
}

func TestEncryptSyncReplacesContainerContent(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("set1", "a.txt"), []byte("A"))
		err := Encrypt(EncryptOptions{
			Password:      "pw-sync",
			ContainerPath: "vault.tre",
			Inputs:        []string{"set1"},
		})
		if err != nil {
			t.Fatalf("initial encrypt failed: %v", err)
		}

		mustWriteFile(t, filepath.Join("set2", "b.txt"), []byte("B"))
		err = Encrypt(EncryptOptions{
			Password:      "pw-sync",
			ContainerPath: "vault.tre",
			Inputs:        []string{"set2"},
			IfExists:      "sync",
		})
		if err != nil {
			t.Fatalf("sync encrypt failed: %v", err)
		}

		if err := os.RemoveAll("set1"); err != nil {
			t.Fatalf("remove set1: %v", err)
		}
		if err := os.RemoveAll("set2"); err != nil {
			t.Fatalf("remove set2: %v", err)
		}

		err = Decrypt(DecryptOptions{Password: "pw-sync", ContainerPath: "vault.tre"})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		if _, err := os.Stat(filepath.Join("set1", "a.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected old sync content to be absent, err=%v", err)
		}
		assertFileContent(t, filepath.Join("set2", "b.txt"), []byte("B"))
	})
}

func TestListReturnsFullPaths(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("src", "nested", "file.txt"), []byte("list-me"))

		err := Encrypt(EncryptOptions{
			Password:      "pw-list",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		entries, err := List(ListOptions{
			Password:      "pw-list",
			ContainerPath: "vault.tre",
		})
		if err != nil {
			t.Fatalf("list failed: %v", err)
		}

		if len(entries) == 0 {
			t.Fatal("expected at least one list entry")
		}

		wantFile, err := filepath.Abs(filepath.Join("src", "nested", "file.txt"))
		if err != nil {
			t.Fatalf("resolve expected abs file path: %v", err)
		}

		found := false
		for _, entry := range entries {
			if entry.Path == wantFile {
				found = true
				if entry.IsDir {
					t.Fatalf("expected file entry for %q", wantFile)
				}
				if entry.Size != int64(len("list-me")) {
					t.Fatalf("unexpected listed size: got %d", entry.Size)
				}
			}
		}

		if !found {
			t.Fatalf("did not find listed file path %q", wantFile)
		}
	})
}

func TestHeaderRoundTrip(t *testing.T) {
	h := containerHeader{
		Magic:       headerMagic,
		Version:     containerVersion,
		KDFMemoryKB: 1024,
		KDFTime:     2,
		KDFThreads:  1,
	}
	copy(h.Salt[:], []byte("0123456789abcdef"))

	buf := &bytes.Buffer{}
	if err := writeHeader(buf, h); err != nil {
		t.Fatalf("write header: %v", err)
	}

	decoded, err := readHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("read header: %v", err)
	}

	if decoded != h {
		t.Fatalf("header mismatch: got %+v want %+v", decoded, h)
	}
}

func TestReadFooterRejectsInvalidBounds(t *testing.T) {
	tempDir := t.TempDir()
	f, err := os.Create(filepath.Join(tempDir, "bad.tre"))
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	padding := make([]byte, 64)
	if _, err := f.Write(padding); err != nil {
		t.Fatalf("write padding: %v", err)
	}

	footer := containerFooter{
		Magic:       footerMagic,
		IndexOffset: 40,
		IndexLength: 40,
	}
	if err := writeFooter(f, footer); err != nil {
		t.Fatalf("write footer: %v", err)
	}

	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek file: %v", err)
	}

	_, err = readFooter(f)
	if err == nil {
		t.Fatal("expected invalid footer bounds error")
	}
}

func withWorkingDir(t *testing.T, dir string, fn func()) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir to temp dir: %v", err)
	}
	defer func() {
		if err := os.Chdir(old); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()
	fn()
}

func mustWriteFile(t *testing.T, relPath string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(relPath), 0o755); err != nil {
		t.Fatalf("mkdir all: %v", err)
	}
	if err := os.WriteFile(relPath, content, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func assertFileContent(t *testing.T, relPath string, expected []byte) {
	t.Helper()
	got, err := os.ReadFile(relPath)
	if err != nil {
		t.Fatalf("read file %q: %v", relPath, err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("file content mismatch for %q: got %q want %q", relPath, got, expected)
	}
}

func readDecryptedIndex(containerPath, password string) (archiveIndex, error) {
	in, err := os.Open(containerPath)
	if err != nil {
		return archiveIndex{}, err
	}
	defer func() { _ = in.Close() }()

	hdr, err := readHeader(in)
	if err != nil {
		return archiveIndex{}, err
	}
	aead, err := buildAEAD(password, hdr)
	if err != nil {
		return archiveIndex{}, err
	}
	footer, err := readFooter(in)
	if err != nil {
		return archiveIndex{}, err
	}

	if _, err := in.Seek(int64(footer.IndexOffset), 0); err != nil {
		return archiveIndex{}, err
	}
	indexCipher := make([]byte, footer.IndexLength)
	if _, err := io.ReadFull(in, indexCipher); err != nil {
		return archiveIndex{}, err
	}

	indexPlain, err := aead.Open(nil, footer.IndexNonce[:], indexCipher, nil)
	if err != nil {
		return archiveIndex{}, err
	}

	var idx archiveIndex
	if err := json.Unmarshal(indexPlain, &idx); err != nil {
		return archiveIndex{}, err
	}
	return idx, nil
}
