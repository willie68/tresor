package tresor

import (
	"compress/gzip"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

func Decrypt(opts DecryptOptions) error {
	if opts.Password == "" {
		return errors.New("password is required")
	}
	if opts.ContainerPath == "" {
		return errors.New("container file is required")
	}

	progressf(opts.ProgressWriter, "decrypt: container=%q", opts.ContainerPath)

	// Create container reader for multi-container support
	cr, err := newContainerReader(opts.ContainerPath)
	if err != nil {
		return err
	}
	defer cr.close()

	hdr, index, err := cr.readIndex(opts.Password)
	if err != nil {
		return err
	}

	aead, err := buildAEAD(opts.Password, hdr)
	if err != nil {
		return err
	}

	if opts.OnFileConflict == nil {
		opts.OnFileConflict = promptFileConflict
	}

	stats := struct {
		decrypted int
		skipped   int
	}{}

	for _, entry := range index.Entries {
		err := decryptProcessEntry(cr, aead, index.ChunkSize, entry, opts.OnFileConflict, opts.ProgressWriter, &stats)
		if err != nil {
			return err
		}
	}

	cr.close()

	if opts.RemoveContainer {
		// Remove all container files
		if err := os.Remove(opts.ContainerPath); err != nil {
			return fmt.Errorf("remove container file: %w", err)
		}
		// Remove sidecar containers
		for i := 0; ; i++ {
			sidecarPath := fmt.Sprintf("%s.%03d", opts.ContainerPath, i)
			if err := os.Remove(sidecarPath); err != nil {
				// If file doesn't exist, we're done with sidecars
				if errors.Is(err, os.ErrNotExist) {
					break
				}
				return fmt.Errorf("remove sidecar %s: %w", sidecarPath, err)
			}
		}
	}

	progressf(opts.ProgressWriter, "decrypt: done (restored=%d skipped=%d)", stats.decrypted, stats.skipped)

	return nil
}

func decryptProcessEntry(cr *containerReader, aead cipher.AEAD, chunkSize uint32, entry archiveEntry, conflictHandler FileConflictHandler, pw io.Writer, stats *struct {
	decrypted int
	skipped   int
}) error {
	target, err := safeOutputPath(entry.Path)
	if err != nil {
		return err
	}
	switch entry.Type {
	case entryTypeDir:
		if err := os.MkdirAll(target, fs.FileMode(entry.Mode)); err != nil {
			return fmt.Errorf("create directory %q: %w", target, err)
		}
	case entryTypeFile:
		resolvedTarget, skip, err := resolveFileConflictTarget(target, conflictHandler)
		if err != nil {
			return err
		}
		if skip {
			stats.skipped++
			progressf(pw, "decrypt: ignore existing %s", target)
			return nil
		}
		progressf(pw, "decrypt: restoring %s", resolvedTarget)
		if err := decryptFileEntry(cr, aead, chunkSize, resolvedTarget, entry); err != nil {
			return err
		}
		stats.decrypted++
	default:
		return fmt.Errorf("unknown entry type %d for %q", entry.Type, entry.Path)
	}
	return nil
}

// matchesFilter checks if a file path matches the given filter pattern.
// Filter types:
// - ".jpg" or ".JPG" etc: matches files with extension .jpg (case insensitive)
// - "*.jpg" or "rep*": matches files with wildcard pattern (glob syntax)
// - "input": matches files containing "input" anywhere in path (case insensitive)
// - "input\\": matches files in directory "input\\" (subdirs of input)
// - "\\input\\": matches files directly in root directory "input\\"

func decryptFileEntry(cr *containerReader, aead cipher.AEAD, chunkSizeFromIndex uint32, target string, entry archiveEntry) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory for %q: %w", target, err)
	}

	storedSize := entry.StoredSize
	if storedSize == 0 {
		storedSize = entry.Size
	}
	if storedSize < 0 {
		return fmt.Errorf("invalid stored size for %q", target)
	}

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(entry.Mode))
	if err != nil {
		return fmt.Errorf("create file %q: %w", target, err)
	}
	defer func() {
		_ = out.Close()
	}()

	// Get the correct container file for this entry
	containerFile, err := cr.getContainerFile(entry.ContainerIndex)
	if err != nil {
		return fmt.Errorf("get container for %q: %w", target, err)
	}

	if _, err := containerFile.Seek(int64(entry.DataOffset), io.SeekStart); err != nil {
		return fmt.Errorf("seek data for %q: %w", target, err)
	}

	encChunkSize := int(chunkSizeFromIndex) + aeadTagSize
	cipherChunk := make([]byte, encChunkSize)
	var restoredStored int64

	var writeDest io.Writer = out
	var tmp *os.File
	if entry.Compressed {
		tmp, err = os.CreateTemp("", "tresor-decrypt-*")
		if err != nil {
			return fmt.Errorf("create temp file for compressed restore: %w", err)
		}
		defer func() {
			name := tmp.Name()
			_ = tmp.Close()
			_ = os.Remove(name)
		}()
		writeDest = tmp
	}

	for i := uint32(0); i < entry.ChunkCount; i++ {
		if _, err := io.ReadFull(containerFile, cipherChunk); err != nil {
			return fmt.Errorf("read encrypted chunk %d for %q: %w", i, target, err)
		}
		nonce := chunkNonce(entry.NonceSeed, i)
		plain, err := aead.Open(nil, nonce[:], cipherChunk, nil)
		if err != nil {
			if isAuthFailure(err) {
				return errors.New("invalid password or corrupted container")
			}
			return fmt.Errorf("decrypt chunk %d for %q: %w", i, target, err)
		}

		remaining := storedSize - restoredStored
		if remaining <= 0 {
			break
		}

		writeLen := int64(len(plain))
		if remaining < writeLen {
			writeLen = remaining
		}

		if _, err := writeDest.Write(plain[:writeLen]); err != nil {
			return fmt.Errorf("write restored chunk for %q: %w", target, err)
		}
		restoredStored += writeLen
	}

	if restoredStored != storedSize {
		return fmt.Errorf("restored stored size mismatch for %q: got %d want %d", target, restoredStored, storedSize)
	}

	if entry.Compressed {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("seek temp file for %q: %w", target, err)
		}
		zr, err := gzip.NewReader(tmp)
		if err != nil {
			return fmt.Errorf("create gzip reader for %q: %w", target, err)
		}
		written, err := io.Copy(out, zr)
		closeErr := zr.Close()
		if err != nil {
			return fmt.Errorf("decompress restored data for %q: %w", target, err)
		}
		if closeErr != nil {
			return fmt.Errorf("finalize gzip stream for %q: %w", target, closeErr)
		}
		if written != entry.Size {
			return fmt.Errorf("restored original size mismatch for %q: got %d want %d", target, written, entry.Size)
		}
	} else if restoredStored != entry.Size {
		return fmt.Errorf("restored size mismatch for %q: got %d want %d", target, restoredStored, entry.Size)
	}

	if entry.ModTime != 0 {
		modTime := time.Unix(entry.ModTime, 0)
		if err := os.Chtimes(target, modTime, modTime); err != nil {
			return fmt.Errorf("restore mod time for %q: %w", target, err)
		}
	}

	return nil
}
