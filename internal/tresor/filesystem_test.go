package tresor

import (
	"bytes"
	"testing"
)

func TestReadOnlyFSReadSmallFile(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create a small test file
		testData := []byte("Hello, World! This is a test file with some content.")
		mustWriteFile(t, "test.txt", testData)

		// Encrypt it into a container
		containerPath := "test.tre"
		err := Encrypt(EncryptOptions{
			Password:      "topsecret",
			ContainerPath: containerPath,
			Inputs:        []string{"test.txt"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// Create ReadOnlyFS
		fs, err := NewReadOnlyFS(containerPath, "topsecret")
		if err != nil {
			t.Fatalf("NewReadOnlyFS failed: %v", err)
		}
		defer fs.Close()

		// Test 1: Read entire file in one go
		buff := make([]byte, len(testData))
		n := fs.Read("test.txt", buff, 0, 0)
		if n < 0 {
			t.Fatalf("Read returned error: %d", n)
		}
		if n != len(testData) {
			t.Errorf("Read returned %d bytes, want %d", n, len(testData))
		}
		if !bytes.Equal(buff[:n], testData) {
			t.Errorf("Read data mismatch.\nGot:  %v\nWant: %v", buff[:n], testData)
		}

		// Test 2: Read with offset
		offset := int64(7)
		expected := testData[offset:]
		buff = make([]byte, len(expected))
		n = fs.Read("test.txt", buff, offset, 0)
		if n < 0 {
			t.Fatalf("Read at offset %d returned error: %d", offset, n)
		}
		if !bytes.Equal(buff[:n], expected) {
			t.Errorf("Read at offset %d mismatch.\nGot:  %v\nWant: %v", offset, buff[:n], expected)
		}

		// Test 3: Read partial
		offset = int64(0)
		length := 5
		expected = testData[:length]
		buff = make([]byte, length)
		n = fs.Read("test.txt", buff, offset, 0)
		if n < 0 {
			t.Fatalf("Read partial returned error: %d", n)
		}
		if !bytes.Equal(buff[:n], expected) {
			t.Errorf("Read partial mismatch.\nGot:  %v\nWant: %v", buff[:n], expected)
		}

		// Test 4: Read partial with offset
		offset = int64(7)
		length = 5
		expected = testData[offset : offset+int64(length)]
		buff = make([]byte, length)
		n = fs.Read("test.txt", buff, offset, 0)
		if n < 0 {
			t.Fatalf("Read partial with offset returned error: %d", n)
		}
		if !bytes.Equal(buff[:n], expected) {
			t.Errorf("Read partial with offset mismatch.\nGot:  %v\nWant: %v", buff[:n], expected)
		}
	})
}

func TestReadOnlyFSReadMultipleSmallFiles(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		// Create multiple small files
		testFiles := map[string][]byte{
			"file1.txt": []byte("File 1 content"),
			"file2.txt": []byte("File 2 - a bit longer"),
			"file3.txt": []byte("F3"),
		}

		for name, data := range testFiles {
			mustWriteFile(t, name, data)
		}

		// Encrypt with explicit file list
		containerPath := "test.tre"
		inputs := []string{}
		for name := range testFiles {
			inputs = append(inputs, name)
		}
		err := Encrypt(EncryptOptions{
			Password:      "topsecret",
			ContainerPath: containerPath,
			Inputs:        inputs,
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		// Create ReadOnlyFS
		fs, err := NewReadOnlyFS(containerPath, "topsecret")
		if err != nil {
			t.Fatalf("NewReadOnlyFS failed: %v", err)
		}
		defer fs.Close()

		// Test each file
		for name, expectedData := range testFiles {
			buff := make([]byte, len(expectedData))
			n := fs.Read(name, buff, 0, 0)
			if n < 0 {
				t.Fatalf("Read %s returned error: %d", name, n)
			}
			if !bytes.Equal(buff[:n], expectedData) {
				t.Errorf("Read %s mismatch.\nGot:  %q\nWant: %q", name, buff[:n], expectedData)
			}
		}
	})
}

func TestReadOnlyFSGetAttrSmallFile(t *testing.T) {
	tempDir := t.TempDir()
	withWorkingDir(t, tempDir, func() {
		testData := []byte("Small file content")
		mustWriteFile(t, "small.txt", testData)

		containerPath := "test.tre"
		err := Encrypt(EncryptOptions{
			Password:      "topsecret",
			ContainerPath: containerPath,
			Inputs:        []string{"small.txt"},
		})
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}

		fs, err := NewReadOnlyFS(containerPath, "topsecret")
		if err != nil {
			t.Fatalf("NewReadOnlyFS failed: %v", err)
		}
		defer fs.Close()

		// Try to read MORE than the file size
		buff := make([]byte, len(testData)+1000)
		n := fs.Read("small.txt", buff, 0, 0)
		if n < 0 {
			t.Fatalf("Read returned error: %d", n)
		}

		// Should only get the actual data, not padding
		if n != len(testData) {
			t.Errorf("Read returned %d bytes, expected exactly %d (no padding)", n, len(testData))
		}

		if !bytes.Equal(buff[:n], testData) {
			t.Errorf("Data mismatch.\nGot:  %q\nWant: %q", buff[:n], testData)
		}
	})
}
