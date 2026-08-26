package tresor

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func Extract(opts ExtractOptions) error {
	if opts.Password == "" {
		return errors.New("password is required")
	}
	if opts.ContainerPath == "" {
		return errors.New("container file is required")
	}
	if opts.ExtractPath == "" {
		return errors.New("extract path is required")
	}

	progressf(opts.ProgressWriter, "extract: container=%q path=%q force-dirs=%v", opts.ContainerPath, opts.ExtractPath, opts.ForceDirs)

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

	// Normalize extract path (convert to forward slashes)
	extractPath := path.Clean(filepath.ToSlash(opts.ExtractPath))

	// Find matching entries
	matchingEntries := make([]archiveEntry, 0)
	for _, entry := range index.Entries {
		entryPath := entry.Path
		// Check if entry matches extract path or is within the extract path
		if entryPath == extractPath || strings.HasPrefix(entryPath, extractPath+"/") {
			matchingEntries = append(matchingEntries, entry)
		}
	}

	if len(matchingEntries) == 0 {
		return fmt.Errorf("no entries found for path %q", opts.ExtractPath)
	}

	if opts.OnFileConflict == nil {
		opts.OnFileConflict = promptFileConflict
	}

	// Check if we're extracting a single file
	isSingleFile := len(matchingEntries) == 1 && matchingEntries[0].Type == entryTypeFile && matchingEntries[0].Path == extractPath

	stats := struct {
		extracted int
		skipped   int
	}{}

	for _, entry := range matchingEntries {
		err := extractProcessEntry(cr, aead, index.ChunkSize, entry, extractPath, isSingleFile, opts.ForceDirs, opts.OnFileConflict, opts.ProgressWriter, &stats)
		if err != nil {
			return err
		}
	}

	cr.close()

	progressf(opts.ProgressWriter, "extract: done (extracted=%d skipped=%d)", stats.extracted, stats.skipped)

	return nil
}

func extractProcessEntry(cr *containerReader, aead cipher.AEAD, chunkSize uint32, entry archiveEntry, extractPath string, isSingleFile, forceDirs bool, conflictHandler FileConflictHandler, pw io.Writer, stats *struct {
	extracted int
	skipped   int
}) error {
	// Skip directories for now (will be created as needed)
	if entry.Type == entryTypeDir {
		if forceDirs {
			target, err := safeOutputPath(entry.Path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(target, fs.FileMode(entry.Mode)); err != nil {
				return fmt.Errorf("create directory %q: %w", target, err)
			}
		}
		return nil
	}

	var targetPath string
	var err error
	if forceDirs {
		// Keep full path structure
		targetPath, err = safeOutputPath(entry.Path)
		if err != nil {
			return err
		}
	} else {
		// Extract only the filename (or relative path from extract point)
		if isSingleFile {
			// For single file, use just the filename
			targetPath = path.Base(entry.Path)
		} else {
			// For directory, strip the extract path prefix and keep relative path
			relPath := strings.TrimPrefix(entry.Path, extractPath+"/")
			targetPath, err = safeOutputPath(relPath)
			if err != nil {
				return err
			}
		}
	}

	// Ensure parent directory exists
	targetDir := filepath.Dir(targetPath)
	if targetDir != "." {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("create parent directory for %q: %w", targetPath, err)
		}
	}

	resolvedTarget, skip, err := resolveFileConflictTarget(targetPath, conflictHandler)
	if err != nil {
		return err
	}
	if skip {
		stats.skipped++
		progressf(pw, "extract: ignore existing %s", targetPath)
		return nil
	}

	progressf(pw, "extract: extracting %s", resolvedTarget)
	if err := decryptFileEntry(cr, aead, chunkSize, resolvedTarget, entry); err != nil {
		return err
	}
	stats.extracted++
	return nil
}
