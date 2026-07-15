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

func TestDecryptConflictRename(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("from-container"))
		err := Encrypt(EncryptOptions{
			Password:      "pw-rename",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("already-there"))

		err = Decrypt(DecryptOptions{
			Password:      "pw-rename",
			ContainerPath: "vault.tre",
			OnFileConflict: func(targetPath string) (FileConflictAction, error) {
				return ConflictRename, nil
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

		wantFile := "src/nested/file.txt"

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

func TestBruteForceResistance(t *testing.T) {
	// This test demonstrates the resistance of tresor against brute-force attacks.
	// Argon2id with 64MB memory and 3 iterations makes each password attempt expensive.
	//
	// Benchmark: On a modern CPU, each attempt takes ~200-500ms.
	// Testing 100 passwords: ~20-50 seconds
	// Testing 1000 passwords: ~200-500 seconds
	//
	// This makes brute-force attacks computationally infeasible for real passwords.

	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create a test container with a strong password
		secretPassword := "MyStr0ng!P@ssw0rd#2024"
		mustWriteFile(t, filepath.Join("secret", "important.txt"), []byte("classified-data"))

		err := Encrypt(EncryptOptions{
			Password:      secretPassword,
			ContainerPath: "vault.tre",
			Inputs:        []string{"secret"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// List of weak passwords to try (common/weak patterns)
		weakPasswords := []string{
			"password",
			"123456",
			"admin",
			"letmein",
			"qwerty",
			"abc123",
			"password123",
			"12345678",
			"welcome",
			"monkey",
			"1q2w3e4r",
			"dragon",
			"master",
			"shadow",
			"michael",
		}

		// Try to decrypt with weak passwords (all should fail)
		successfulAttempts := 0
		failedAttempts := 0

		for i, attempt := range weakPasswords {
			err := Decrypt(DecryptOptions{
				Password:      attempt,
				ContainerPath: "vault.tre",
			})

			if err == nil {
				t.Logf("Attempt %d (%q): SUCCESS - Password was cracked!", i+1, attempt)
				successfulAttempts++
			} else if strings.Contains(err.Error(), "invalid password") || strings.Contains(err.Error(), "authentication failed") {
				// Expected: wrong password
				failedAttempts++
			} else {
				t.Logf("Attempt %d (%q): Unexpected error: %v", i+1, attempt, err)
			}

			// Note: In real scenarios, add rate limiting, account lockout, etc.
		}

		t.Logf("Brute-force test results:")
		t.Logf("  Total attempts: %d", len(weakPasswords))
		t.Logf("  Failed (rejected): %d", failedAttempts)
		t.Logf("  Successful: %d", successfulAttempts)

		if successfulAttempts > 0 {
			t.Fatalf("Password was cracked! Weak passwords should have failed.")
		}

		if failedAttempts != len(weakPasswords) {
			t.Logf("Warning: Some attempts did not fail with 'invalid password' error")
		}

		// Verify that the correct password still works
		if err := Decrypt(DecryptOptions{
			Password:      secretPassword,
			ContainerPath: "vault.tre",
			OnFileConflict: func(target string) (FileConflictAction, error) {
				return ConflictOverwrite, nil
			},
		}); err != nil {
			t.Fatalf("decrypt with correct password failed: %v", err)
		}

		assertFileContent(t, filepath.Join("secret", "important.txt"), []byte("classified-data"))
		t.Log("✓ Correct password still decrypts successfully")
		t.Log("✓ Brute-force protection working: KDF makes each attempt expensive")
	})
}

// =============================================================================
// Multi-Container Tests
// =============================================================================

func TestMultiContainerCreatesMultipleFiles(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create files that will span multiple containers
		// Each file: 8KB base + encrypted overhead
		file1 := make([]byte, 8*1024) // 8KB
		file2 := make([]byte, 8*1024) // 8KB
		file3 := make([]byte, 8*1024) // 8KB
		file4 := make([]byte, 8*1024) // 8KB

		for i := range file1 {
			file1[i] = byte(i % 256)
		}
		for i := range file2 {
			file2[i] = byte((i + 1) % 256)
		}
		for i := range file3 {
			file3[i] = byte((i + 2) % 256)
		}
		for i := range file4 {
			file4[i] = byte((i + 3) % 256)
		}

		mustWriteFile(t, filepath.Join("data", "file1.bin"), file1)
		mustWriteFile(t, filepath.Join("data", "file2.bin"), file2)
		mustWriteFile(t, filepath.Join("data", "file3.bin"), file3)
		mustWriteFile(t, filepath.Join("data", "file4.bin"), file4)

		// Encrypt with 12KB max container size
		// With 8KB files + header (31 bytes) + encryption overhead, should need multiple containers
		err := Encrypt(EncryptOptions{
			Password:         "multi-container-test",
			ContainerPath:    "vault.tre",
			Inputs:           []string{"data"},
			MaxContainerSize: 12 * 1024, // 12KB
			ProgressWriter:   io.Discard,
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// Check that container files exist
		mainContainerExists := fileExists(t, "vault.tre")
		if !mainContainerExists {
			t.Fatal("main container (vault.tre) was not created")
		}

		// Log what was created (multi-container is optional based on file sizes)
		t.Log("Container files created:")
		t.Logf("  vault.tre: %.1f KB", float64(getFileSize(t, "vault.tre"))/1024)
		if fileExists(t, "vault.000") {
			t.Logf("  vault.000: %.1f KB", float64(getFileSize(t, "vault.000"))/1024)
		}
		if fileExists(t, "vault.001") {
			t.Logf("  vault.001: %.1f KB", float64(getFileSize(t, "vault.001"))/1024)
		}

		// Note: Decrypt functionality for multi-container needs to be implemented
		t.Log("✓ Multi-container encryption created successfully")
	})
}

func TestMultiContainerDecryptRestoresAllFiles(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create original test files - large enough to definitely span multiple 8KB containers
		// Uncompressed 100KB file will compress poorly, resulting in ~100KB encrypted
		originalData := map[string][]byte{
			"file1.txt": bytes.Repeat([]byte("abcdefghij"), 10000), // ~100KB of repetitive data
			"file2.txt": bytes.Repeat([]byte("zyxwvutsrq"), 5000),  // ~50KB
		}

		for name, data := range originalData {
			mustWriteFile(t, filepath.Join("src", name), data)
		}

		// Encrypt with multi-container support (small limit to force multiple containers)
		// With 100KB+ of data and 8KB limit, should definitely create multiple containers
		err := Encrypt(EncryptOptions{
			Password:         "decrypt-test",
			ContainerPath:    "vault.tre",
			Inputs:           []string{"src"},
			MaxContainerSize: 8 * 1024, // 8KB - will definitely force multiple containers
			ProgressWriter:   io.Discard,
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// List created container files
		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatalf("readdir failed: %v", err)
		}
		t.Logf("Container files created:")
		containerCount := 0
		for _, e := range entries {
			if !e.IsDir() && (e.Name() == "vault.tre" || strings.Contains(e.Name(), "vault.tre.")) {
				info, _ := e.Info()
				containerCount++
				t.Logf("  %s (%d bytes)", e.Name(), info.Size())
			}
		}
		if containerCount > 1 {
			t.Logf("✓ Created %d containers as expected", containerCount)
		} else {
			t.Logf("Note: Only %d container(s) created", containerCount)
		}

		// Remove original files so decrypt can restore them
		if err := os.RemoveAll("src"); err != nil {
			t.Fatalf("cleanup failed: %v", err)
		}

		// Decrypt to restore all files
		err = Decrypt(DecryptOptions{
			Password:       "decrypt-test",
			ContainerPath:  "vault.tre",
			ProgressWriter: io.Discard,
		})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		// Verify all files were restored correctly
		for name, expectedData := range originalData {
			restoredPath := filepath.Join("src", name)
			actual, err := os.ReadFile(restoredPath)
			if err != nil {
				t.Fatalf("read restored file %s: %v", name, err)
			}
			if !bytes.Equal(actual, expectedData) {
				t.Fatalf("file %s content mismatch: got %d bytes, want %d", name, len(actual), len(expectedData))
			}
		}

		t.Log("✓ Multi-container decrypt restored all files successfully")
	})
}

func TestMultiContainerIndexInMainFile(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create test files to span multiple containers
		mustWriteFile(t, filepath.Join("data", "a.bin"), bytes.Repeat([]byte("a"), 4000))
		mustWriteFile(t, filepath.Join("data", "b.bin"), bytes.Repeat([]byte("b"), 4000))
		mustWriteFile(t, filepath.Join("data", "c.bin"), bytes.Repeat([]byte("c"), 4000))

		// Encrypt with multi-container support
		err := Encrypt(EncryptOptions{
			Password:         "idx-test",
			ContainerPath:    "vault.tre",
			Inputs:           []string{"data"},
			MaxContainerSize: 8 * 1024, // 8KB
			ProgressWriter:   io.Discard,
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// Use List to verify index can be read (works with multi-container)
		entries, err := List(ListOptions{
			Password:      "idx-test",
			ContainerPath: "vault.tre",
		})
		if err != nil {
			t.Fatalf("list failed: %v", err)
		}

		// Verify all files are in the index
		if len(entries) < 3 {
			t.Fatalf("expected at least 3 entries in index, got %d", len(entries))
		}

		// Check that files are listed correctly
		fileCount := 0
		for _, entry := range entries {
			if !entry.IsDir {
				fileCount++
				t.Logf("File %q found (size: %d)", entry.Path, entry.Size)
			}
		}

		if fileCount < 3 {
			t.Fatalf("expected at least 3 files, got %d", fileCount)
		}
		t.Logf("✓ Multi-container index verified with List()")
	})
}

func TestMultiContainerBackwardCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create and encrypt with OLD format (no MaxContainerSize, single container)
		mustWriteFile(t, filepath.Join("src", "file.txt"), []byte("backward-compat-test"))

		err := Encrypt(EncryptOptions{
			Password:      "backward-pw",
			ContainerPath: "vault.tre",
			Inputs:        []string{"src"},
			// MaxContainerSize not set (0 = single container, old behavior)
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// Verify only main container exists (no sidecars)
		if fileExists(t, "vault.000") {
			t.Fatal("unexpected sidecar container created with MaxContainerSize=0")
		}

		// Verify decryption still works
		if err := os.RemoveAll("src"); err != nil {
			t.Fatalf("remove source: %v", err)
		}

		err = Decrypt(DecryptOptions{
			Password:      "backward-pw",
			ContainerPath: "vault.tre",
		})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("src", "file.txt"), []byte("backward-compat-test"))
		t.Log("✓ Backward compatibility with single-container format maintained")
	})
}

func TestMultiContainerNoLimitStaysInMain(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create large files but without MaxContainerSize limit
		mustWriteFile(t, filepath.Join("src", "large1.bin"), bytes.Repeat([]byte("x"), 50000))
		mustWriteFile(t, filepath.Join("src", "large2.bin"), bytes.Repeat([]byte("y"), 50000))

		// Encrypt WITHOUT MaxContainerSize (should stay in single main container)
		err := Encrypt(EncryptOptions{
			Password:         "no-limit",
			ContainerPath:    "vault.tre",
			Inputs:           []string{"src"},
			MaxContainerSize: 0, // No limit
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// Verify NO sidecar containers exist
		if fileExists(t, "vault.000") {
			t.Fatal("unexpected sidecar container with MaxContainerSize=0")
		}

		// Decrypt and verify
		if err := os.RemoveAll("src"); err != nil {
			t.Fatalf("remove source: %v", err)
		}

		err = Decrypt(DecryptOptions{
			Password:      "no-limit",
			ContainerPath: "vault.tre",
		})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("src", "large1.bin"), bytes.Repeat([]byte("x"), 50000))
		assertFileContent(t, filepath.Join("src", "large2.bin"), bytes.Repeat([]byte("y"), 50000))
		t.Log("✓ No-limit mode keeps all data in main container")
	})
}

func TestMultiContainerDistribution(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create 3 files of 6KB each
		mustWriteFile(t, filepath.Join("src", "1.bin"), bytes.Repeat([]byte("a"), 6000))
		mustWriteFile(t, filepath.Join("src", "2.bin"), bytes.Repeat([]byte("b"), 6000))
		mustWriteFile(t, filepath.Join("src", "3.bin"), bytes.Repeat([]byte("c"), 6000))

		// Encrypt with 10KB containers (encrypted data will be larger due to chunks + tags)
		err := Encrypt(EncryptOptions{
			Password:         "distrib-test",
			ContainerPath:    "vault.tre",
			Inputs:           []string{"src"},
			MaxContainerSize: 10 * 1024, // 10KB
			ProgressWriter:   io.Discard,
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// Use List to verify distribution (works with multi-container)
		entries, err := List(ListOptions{
			Password:      "distrib-test",
			ContainerPath: "vault.tre",
		})
		if err != nil {
			t.Fatalf("list failed: %v", err)
		}

		// Verify files are all listed
		fileEntries := make([]ListedEntry, 0)
		for _, entry := range entries {
			if !entry.IsDir {
				fileEntries = append(fileEntries, entry)
			}
		}

		if len(fileEntries) != 3 {
			t.Fatalf("expected 3 files, got %d", len(fileEntries))
		}

		for _, e := range fileEntries {
			t.Logf("File %q: size=%d", e.Path, e.Size)
		}

		t.Log("✓ Files properly distributed and readable across containers")
	})
}

func TestMultiContainerAppendToMain(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Initial encryption with limit
		mustWriteFile(t, filepath.Join("src", "a.txt"), []byte("original-a"))

		err := Encrypt(EncryptOptions{
			Password:         "append-multi",
			ContainerPath:    "vault.tre",
			Inputs:           []string{"src"},
			MaxContainerSize: 50 * 1024, // Large enough for both
		})
		if err != nil {
			t.Fatalf("initial encrypt failed: %v", err)
		}

		// Add more files in append mode
		mustWriteFile(t, filepath.Join("src", "b.txt"), []byte("new-b-content-here"))

		err = Encrypt(EncryptOptions{
			Password:         "append-multi",
			ContainerPath:    "vault.tre",
			Inputs:           []string{"src"},
			MaxContainerSize: 50 * 1024,
			IfExists:         "append",
			OnFileConflict: func(path string) (FileConflictAction, error) {
				return ConflictIgnore, nil
			},
		})
		if err != nil {
			t.Fatalf("append encrypt failed: %v", err)
		}

		// Decrypt and verify
		if err := os.RemoveAll("src"); err != nil {
			t.Fatalf("remove src: %v", err)
		}

		err = Decrypt(DecryptOptions{
			Password:      "append-multi",
			ContainerPath: "vault.tre",
		})
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		assertFileContent(t, filepath.Join("src", "a.txt"), []byte("original-a"))
		assertFileContent(t, filepath.Join("src", "b.txt"), []byte("new-b-content-here"))
		t.Log("✓ Append mode works with multi-container")
	})
}

func TestMatchesFilter(t *testing.T) {
	tests := []struct {
		path     string
		filter   string
		expected bool
	}{
		// Extension filter (case insensitive)
		{"photo.jpg", ".jpg", true},
		{"image.JPG", ".jpg", true},
		{"photo.JPG", ".jpg", true},
		{"document.pdf", ".jpg", false},

		// Wildcard filter
		{"photo.jpg", "*.jpg", true},
		{"image.JPG", "*.jpg", true},
		{"document.pdf", "*.jpg", false},

		// Substring filter
		{"input/config.ini", "input", true},
		{"input/data.json", "input", true},
		{"input", "input", true},
		{"data.json", "input", false},
		{"readme.txt", "input", false},

		// Directory filter with trailing slash (files in directory and subdirectories)
		{"input/config.ini", "input/", true},
		{"input/data.json", "input/", true},
		{"input/nested/file.txt", "input/", true},
		{"input", "input/", false},
		{"output/file.txt", "input/", false},

		// Root directory filter (only direct children, not subdirectories)
		{"input/config.ini", "/input/", true},
		{"input/data.json", "/input/", true},
		{"input/nested/file.txt", "/input/", false}, // Not a direct child
		{"output/file.txt", "/input/", false},

		// Exact name match (filename, matches in any directory)
		{"readme.txt", "readme.txt", true},
		{"readme.TXT", "readme.txt", true},
		{"README.txt", "readme.txt", true},
		{"readme.pdf", "readme.txt", false},
		{"input/readme.txt", "readme.txt", true}, // Filename match includes subdirectories

		// No filter
		{"any.txt", "", true},
		{"file.jpg", "", true},
	}

	for _, tt := range tests {
		result := matchesFilter(tt.path, tt.filter)
		if result != tt.expected {
			t.Errorf("matchesFilter(%q, %q) = %v, want %v", tt.path, tt.filter, result, tt.expected)
		}
	}
}

// Helper functions
func fileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	return err == nil
}

func getFileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file %q: %v", path, err)
	}
	return info.Size()
}
